<?php

namespace A17\Twill\Http\ViewComposers;

use Illuminate\Config\Repository as Config;
use Illuminate\Contracts\View\View;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Session\Store as SessionStore;

class FilesUploaderConfig
{
    /**
     * @var UrlGenerator
     */
    protected $urlGenerator;

    /**
     * @var Config
     */
    protected $config;

    /**
     * @var SessionStore
     */
    protected $sessionStore;

    public function __construct(UrlGenerator $urlGenerator, Config $config, SessionStore $sessionStore)
    {
        $this->urlGenerator = $urlGenerator;
        $this->config = $config;
        $this->sessionStore = $sessionStore;
    }

    /**
     * Binds data to the view.
     *
     * @return void
     */
    public function compose(View $view)
    {
        $libraryDisk = $this->config->get('twill.file_library.disk');
        $endpointType = $this->config->get('twill.file_library.endpoint_type');
        $allowedExtensions = $this->config->get('twill.file_library.allowed_extensions');

        // anonymous functions are used to let configuration dictate
        // the execution of the appropriate implementation
        $endpointByType = [
            'local' => function () {
                return $this->urlGenerator->route(config('twill.admin_route_name_prefix') . 'file-library.files.store');
            },
            's3' => function () use ($libraryDisk) {
                return s3Endpoint($libraryDisk);
            },
            'azure' => function () use ($libraryDisk) {
                return azureEndpoint($libraryDisk);
            },
        ];

        $signatureEndpointByType = [
            'local' => null,
            's3' => $this->urlGenerator->route(config('twill.admin_route_name_prefix') . 'file-library.sign-s3-upload'),
            'azure' => $this->urlGenerator->route(config('twill.admin_route_name_prefix') . 'file-library.sign-azure-upload'),
        ];

        $accessKey = $this->config->get('filesystems.disks.' . $libraryDisk . '.key', 'none');
        $sessionToken = null;
        $sessionTokenExpiration = null;
        
        if ($endpointType === 's3') {
            // CacheInterface|array|bool|callable
            $diskSettingCreds = $this->config->get('filesystems.disks.' . $libraryDisk . '.credentials');
            // it's a memoized credential provider
            if (!empty($diskSettingCreds) && is_callable($diskSettingCreds)) {
                $diskSettingCreds = $diskSettingCreds->call();
            }
            // it's a cacher object
            if (!empty($diskSettingCreds) && is_object($diskSettingCreds) && method_exists($diskSettingCreds, 'get')) {
                $diskSettingCreds = $diskSettingCreds->get('aws_cached_web_identity_credentials');
            }
            // it's a credential object
            if (!empty($diskSettingCreds) && is_object($diskSettingCreds) && method_exists($diskSettingCreds, 'getAccessKeyId')) {
                $accessKey = $diskSettingCreds->getAccessKeyId();
                $sessionToken = $diskSettingCreds->getSecurityToken();
                $sessionTokenExpiration = $diskSettingCreds->getExpiration();
            // it's an array
            } else if (!empty($diskSettingCreds) && is_array($diskSettingCreds)) {
                $accessKey = $diskSettingCreds['key'];
                $sessionToken = $diskSettingCreds['token'];
                $sessionTokenExpiration = $diskSettingCreds['expiration'];
            }
        }

        $filesUploaderConfig = [
            'endpointType' => $endpointType,
            'endpoint' => $endpointByType[$endpointType](),
            'successEndpoint' => $this->urlGenerator->route(config('twill.admin_route_name_prefix') . 'file-library.files.store'),
            'signatureEndpoint' => $signatureEndpointByType[$endpointType],
            'endpointBucket' => $this->config->get('filesystems.disks.' . $libraryDisk . '.bucket', 'none'),
            'endpointRegion' => $this->config->get('filesystems.disks.' . $libraryDisk . '.region', 'none'),
            'endpointRoot' => $endpointType === 'local' ? '' : $this->config->get('filesystems.disks.' . $libraryDisk . '.root', ''),
            'accessKey' => $accessKey,
            'sessionToken' => $sessionToken,
            'sessionTokenExpiration' => $sessionTokenExpiration,
            'csrfToken' => $this->sessionStore->token(),
            'acl' => $this->config->get('twill.file_library.acl'),
            'filesizeLimit' => $this->config->get('twill.file_library.filesize_limit'),
            'allowedExtensions' => $allowedExtensions,
        ];

        $view->with(['filesUploaderConfig' => $filesUploaderConfig]);
    }
}
