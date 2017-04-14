<?php

namespace OAuth\OAuth2\Service;

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
class SPiD extends AbstractService
{
    const SCOPE_MERCHANTS_WRITE = 'spid:merchants|write';

    private $environment;

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null
    ) {

        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);
        $this->environment = config('oauth-5-laravel.consumers.SPiD.environment', 'https://identity-pre.schibsted.com/');
        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri($this->environment . 'api/2/');
        }
    }

    public function isValidScope($scope)
    {
        return true;
    }


    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri($this->environment . 'flow/auth');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri($this->environment . 'oauth/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        $token->setLifeTime($data['expires_in']);

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        unset($data['access_token']);
        unset($data['expires_in']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * @param null $returnTo
     * @return Uri
     */
    public function getLogoutUrl($returnTo = null) {
        $returnTo = is_null($returnTo) ? \URL::current() : $returnTo;
        $uri = new Uri($this->environment . 'logout');
        $uri->addToQuery('client_id', $this->credentials->getConsumerId());
        $uri->addToQuery('redirect_uri', $returnTo);
        return $uri;
    }
}
