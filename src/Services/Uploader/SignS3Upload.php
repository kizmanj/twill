<?php

namespace A17\Twill\Services\Uploader;

use Illuminate\Config\Repository as Config;

class SignS3Upload
{
    private $bucket;

    private $secret;

    /**
     * @var Config
     */
    protected $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function fromPolicy($policy, SignUploadListener $listener, $disk = 'libraries')
    {
        $policyObject = json_decode($policy, true);
        $policyJson = json_encode($policyObject);

        $this->bucket = $this->config->get('filesystems.disks.' . $disk . '.bucket');

        $diskSettingCreds = $this->config->get('filesystems.disks.' . $disk . '.credentials');
        if (!empty($diskSettingCreds)) {
            // it's a memoized credential provider
            if (!empty($diskSettingCreds) && is_callable($diskSettingCreds)) {
                $diskSettingCreds = $diskSettingCreds->call();
            }
            // it's a cacher object
            if (!empty($diskSettingCreds) && is_object($diskSettingCreds) && method_exists($diskSettingCreds, 'get')) {
                $diskSettingCreds = $diskSettingCreds->get('aws_cached_web_identity_credentials');
            }
            $this->secret = $diskSettingCreds->getSecretKey();
        } else {
            $this->secret = $this->config->get('filesystems.disks.' . $disk . '.secret');
        }

        $signedPolicy = $this->signPolicy($policyJson);

        if ($signedPolicy) {
            return $listener->uploadIsSigned($signedPolicy);
        }

        return $listener->uploadIsNotValid();
    }

    private function signPolicy($policyJson)
    {
        $policyObject = json_decode($policyJson, true);

        if ($this->isValid($policyObject)) {
            $encodedPolicy = base64_encode($policyJson);
            $signedPolicy = [
                'policy' => $encodedPolicy,
                'signature' => $this->signV4Policy($policyObject, $encodedPolicy),
            ];

            return $signedPolicy;
        }

        return null;
    }

    private function isValid($policy)
    {
        $expectedMaxSize = null;
        $conditions = $policy['conditions'];
        $bucket = null;
        $parsedMaxSize = null;

        foreach ($conditions as $condition) {
            if (isset($condition['bucket'])) {
                $bucket = $condition['bucket'];
            } elseif (isset($condition[0]) && $condition[0] == 'content-length-range') {
                $parsedMaxSize = $condition[2];
            }
        }

        return $bucket == $this->bucket && $parsedMaxSize == (string) $expectedMaxSize;
    }

    private function signV4Policy($policy, $encodedPolicy)
    {
        foreach ($policy['conditions'] as $condition) {
            if (isset($condition['x-amz-credential'])) {
                $credentialCondition = $condition['x-amz-credential'];
            }
        }

        $pattern = "/.+\/(.+)\\/(.+)\/s3\/aws4_request/";
        preg_match($pattern, $credentialCondition ?? '', $matches);

        $dateKey = hash_hmac('sha256', $matches[1], 'AWS4' . $this->secret, true);
        $dateRegionKey = hash_hmac('sha256', $matches[2], $dateKey, true);
        $dateRegionServiceKey = hash_hmac('sha256', 's3', $dateRegionKey, true);
        $signingKey = hash_hmac('sha256', 'aws4_request', $dateRegionServiceKey, true);

        return hash_hmac('sha256', $encodedPolicy, $signingKey);
    }
}
