<?php

namespace OAuth\OAuth2\Service;

use App\Http\Exception\AccessDeniedException;
use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

/**
 * SPiD OAuth service.
 *
 * @author Grzegorz Kurtyka <grzegorz.kurtka@schibsted.pl>
 * @link https://techdocs.spid.no
 */
class SchibstedAccount extends SPiD
{
    protected $environment;

    protected $acrValues = ['pwd'];

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {

        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);
        $this->scopes[] = 'openid';
        $this->environment = config(
            'oauth-5-laravel.consumers.SchibstedAccount.environment',
            'https://identity-pre.schibsted.com/'
        );
        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri($this->environment);
        }
    }

    public function setACRValues($acrValues) {
        $this->acrValues = $acrValues;
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        $uri = new Uri($this->environment . 'oauth/authorize');
        $uri->addToQuery('new-flow', 'true');
        $uri->addToQuery('acr_values', implode(' ', $this->acrValues));
        return $uri;
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri($this->environment . 'oauth/token');
    }

}
