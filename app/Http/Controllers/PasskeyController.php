<?php

namespace App\Http\Controllers;

use App\Models\Passkey;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Session;
use Illuminate\Validation\ValidationException;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;

class PasskeyController extends Controller
{
    public function authenticate(Request $request)
    {
        $request->validate(['answer' => ['required', 'json']]);

        $requestCeremony = (new CeremonyStepManagerFactory)->requestCeremony();

        $attestationStatementSupportManager = new AttestationStatementSupportManager;
        $webauthnSerializerFactory = (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();

        /** @var PublicKeyCredential $publicKeyCredential */
        $publicKeyCredential = $webauthnSerializerFactory->deserialize($request->answer, PublicKeyCredential::class, 'json');

        if (! $publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            return to_route('profile.edit')->withFragment('managePasskeys');
        }

        $passkey = Passkey::firstWhere('credential_id', $publicKeyCredential->rawId);

        if (! $passkey) {
            throw ValidationException::withMessages(['answer' => 'This passkey is not valid']);
        }

        try {
            $publicKeyCredentialSource = AuthenticatorAssertionResponseValidator::create($requestCeremony)->check(
                publicKeyCredentialSource: $passkey->data,
                authenticatorAssertionResponse: $publicKeyCredential->response,
                publicKeyCredentialRequestOptions: Session::get('passkey-authentication-options'),
                host: $request->getHost(),
                userHandle: null
            );
        } catch (Throwable $e) {
            throw ValidationException::withMessages([
                'name' => 'The given key is invalid.',
            ]);
        }

        $passkey->update([
            'data' => $publicKeyCredentialSource,
        ]);

        Auth::loginUsingId($passkey->user_id);
        $request->session()->regenerate();

        return to_route('dashboard');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $data = $request->validateWithBag('createPasskey', [
            'name' => ['required', 'string', 'max:255'],
            'passkey' => ['required', 'json'],
        ]);

        $csmFactory = new CeremonyStepManagerFactory;
        $creationCSM = $csmFactory->creationCeremony();

        $attestationStatementSupportManager = new AttestationStatementSupportManager;
        $webauthnSerializerFactory = (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();

        /** @var PublicKeyCredential $publicKeyCredential */
        $publicKeyCredential = $webauthnSerializerFactory->deserialize($request->passkey, PublicKeyCredential::class, 'json');

        if (! $publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            return to_route('login');
        }

        try {
            $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create($creationCSM)->check(
                authenticatorAttestationResponse: $publicKeyCredential->response,
                publicKeyCredentialCreationOptions: Session::get('passkey-registration-options'),
                host: $request->getHost(),
            );
        } catch (Throwable $e) {
            throw ValidationException::withMessages([
                'name' => 'The given key is invalid.',
            ])->errorBag('createPasskey');
        }

        $request->user()->passkeys()->create([
            'name' => $data['name'],
            'data' => $publicKeyCredentialSource,
        ]);

        return to_route('profile.edit')->withFragment('managePasskeys');
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Passkey $passkey)
    {
        Gate::authorize('delete', $passkey);

        $passkey->delete();

        return back();
    }
}
