# Proposal for advanced JSON Login - Part 2

The [advanced JSON login protocol](https://pad.gnome.org/ktbmfv4FQ8SbFb-lc4K8Dw) mechanism allows us to start moving away from PAM. Here's how that would work, at a high level

## `io.systemd.AuthenticationProvider`

This Varlink interface has a single method: `Authenticate(username | uid)`. It returns multiple values:

1. First it sends over the file descriptor. This can be sent off to the frontend
2. Later, once the frontend has finished authentication, it returns either a `AuthenticationFailed` error or success. In the success case, it returns a blob of data to be used for things like home directory encryption/decryption and whatnot.

The providers are dropped into `/run/systemd/auth-provider/[name]`. You can decide which provider should be used by looking at the `authService` field of the user's user record.

## `/usr/lib/systemd/systemd-authd-pam-bridge`

For various display managers to port to this new mechanism, they need to be able to maintain compatibility with users that don't have an `AuthenticationProvider` associated and potentially some custom PAM authentication plugin (i.e. imagine someone who previously implemented two-factor by having `pam_unix.so` followed by `pam_google_authenticator.so`). To that end, we need to have backwards-compatibility for running things like this.

This is what `systemd-authd-pam-bridge` is for. If we don't have an `AuthenticationProvider` associated with a given user, then each service (GDM, Plasma DM/SDDM, LightDM, etc) can fall back to PAM.

The binary would take one argument, and that's the PAM stack to run. It runs that PAM stack, and then translates the PAM conversation into the new JSON protocol.

If we're feeling adventurous, we could implement some of GDM's PAM extesnsion. Specifically, I've got the GDM Chooser extension in mind. If we're feeling extra adventurous, we could try implementing the various GDM JSON extensions as well (i.e. the authd protocol and SSSD protocol). Though it might be better for SSSD and authd to just port to the new JSON protocol.

We should also support the extension that is used to tunnel the new advanced JSON protocol through PAM. That way we can transparently pass through any PAM modules that are capable of the advanced JSON protocol.

## `/run/systemd/io.systemd.Authenticator`

This is a for-convenience Varlink service that implements the `AuthenticationProvider` interface, that you can call and will work with any username.

First thing it does is looks up the provided username or UID via userdb to find the appropriate `AuthenticationProvider` service. If one isn't found, it forks off `systemd-authd-pam-bridge` with the `systemd-authd` PAM service and uses that instead

Then it just proxies through the Varlink calls.

## `/run/systemd/auth-provider/io.systemd.Userdb`

This is a basic authentication provider that works based on information encoded into a `userdb` user record. This is basically homed's authentication logic extracted out of homed so that it can be used via this generic mechanism.

Conceptually, this is to userdb as `pam_unix` is to shadow.

## `pam_systemd_authenticationd.so`

This is for retrofitting authenticationd into PAM. Implementation would be as follows.

First, we'd need to find the `AuthenticationProvider` to use. We can't just call into `io.systemd.Authenticator` because we want to avoid going from PAM -> systemd-authd -> PAM and potentially getting stuck in a loop. So instead we manually look up the user and try to use their authenticator. If they don't have one, we return a PAM error indicating that the module is currently unavailable.

The module would basically run as the "frontend" for the new JSON protocol from within the PAM module. We'd translate the various mechanisms into text-based prompts and back.

This exists so that SSHD, and other services that use PAM for authentication, can work with all the fancy new authenticators. Even with reduced functionality.

## Polkit

Polkit is a service that uses PAM but we can cut PAM out of the equation while massively boosting Polkit's ability to deal with fancy authentication methods.

Basically, Polkit would just connect to the `io.systemd.Authenticate` Varlink service and ask it to authenticate. The service gives Polkit an FD, which gets forwarded to the Polkit agent (gnome-shell) for display. Then polkit waits for the final yes/no answer from Varlink, and uses that to approve or deny the action we're prompting for

## Maybe: `io.systemd.AuthenticationPrompter`

Since there's one graphical session per user allowed, we can define some path `/run/user/<uid>/io.systemd.AuthenticationPrompter` with some trivial Varlink service that does nothing but recieve an FD and show the authentication prompt.

This might be useful as we plumb through the protocol into other places, potentially
- systemd-ask-password?
- Polkit (which would replace its agents with this)
- SSH agent, so that fancy auth over SSH could use a fancy UI?
- Keyring unlocking?
- Passkeys (credentials-for-linux project) (you traditionally enter your own user password or authenticate with fingerprint / etc to unlock the WebAuthn platform authenticator)?
- Remote desktop?
- We could probably provide this as an API for apps to use?
- Flatpak could use this for app locking?
- machined / nspawn / vmspawn might want to proxy their login prompts through a GUI as well, maybe? Or maybe enable encrypted containers/VMs this way?

Would be a pain for all of these services to have to maintain their own scheme for finding the DE to be able to pass in the JSON FD.

On the other hand, something like Polkit should probably be handled by a UI running _outside_ of the session. Maybe that's something that the path in `/run` can coordinate, though. For instance: we ask `gnome-shell` for a polkit prompt, `gnome-shell` takes a screenshot and blurs it, then asks GDM to show a polkit prompt (passing along the JSON FD)
