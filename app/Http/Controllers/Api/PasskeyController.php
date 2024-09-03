<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Passkey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Illuminate\Support\Str;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PublicKey;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;

class PasskeyController extends Controller
{
    public function registerOptions(Request $request)
    {
        $request->validateWithBag('createPasskey', [
            'name' => ['required', 'string', 'max:255'],
        ]);

        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: parse_url(config('app.url'), PHP_URL_HOST)
            ),
            user: new PublicKeyCredentialUserEntity(
                name: $request->user()->email,
                id: $request->user()->id,
                displayName: $request->user()->name
            ),
            challenge: Str::random(),
        );

        Session::flash('passkey-registration-options', $options);

        return (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create()
        ))->create()->serialize(data: $options, format: 'json');
    }

    public function authenticationOptions(Request $request)
    {
        $allowedCredentials = $request->filled('email') ? Passkey::whereRelation('user', 'email', $request->email)
            ->get()
            ->map(fn(Passkey $passkey) => $passkey->data)
            ->map(fn(PublicKeyCredentialSource $source) => $source->getPublicKeyCredentialDescriptor())->all()
            : [];

        $options = new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: parse_url(config('app.url'), PHP_URL_HOST),
            allowCredentials: $allowedCredentials
        );

        Session::flash('passkey-authentication-options', $options);

        return (new WebauthnSerializerFactory(
            AttestationStatementSupportManager::create()
        ))->create()->serialize(data: $options, format: 'json');
    }
}
