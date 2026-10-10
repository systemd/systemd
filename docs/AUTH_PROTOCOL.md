# Proposal for alternative design for JSON messages

This is a proposal for a new JSON-based authentication protocol for GDM (and, eventually, the systemd upstream replacement for GDM and other desktop-specific display managers). The authenticator 

This protocol is event driven. Basically, the two parties (the authenticator, which I'll be calling the "broker". And the frontend, which I'll be calling "GDM") will pass events back and forth at each other as things happen. Events have a basic structure:

```js
{
    "event": [some event],
    [arguments]
}
```

## PAM

PAM is not event-driven, but instead it acts as a blocking conversation: request, response. Next request, next response. We also need to consider a future beyond PAM. So, this protocol happens entirely outside of the PAM context. Here's how we retrofit the protocol into PAM.

Basically, we'd spin up a specific PAM service and wait for the first question it sends us. That first question might be a normal PAM question, at which point we fall back to legacy PAM behavior. It might be a switchable auth JSON request (i.e. org.gnome.DisplayManager.UserVerifier.CustomJSON, "auth-mechanisms" v1), at which point we go down the GDM switchable auth route (GNOME 50). Or it might be an "upgrade-to-fd" request (e.g. org.gnome.DisplayManager.UserVerifier.SwitchToFd), at which point we do the following:

The `io.systemd.SwitchToFd` PAM extension would just contain an FD number. Alternatively, we could use a GDM `CustomJSON` type message, with a protocol of `"switch-to-fd"` and version of 1 (where the JSON would specify an FD number). Either way, we get an FD number. I think I prefer the systemd idea, though, because of what comes next (getting rid of PAM). But that's for the [Part 2 document](AUTH_API.md) to discuss.

Now, since PAM modules are in-process libraries, they can obtain the FD from wherever and open it in the gdm-session-worker's process space. So, the gdm-session-worker will have this FD just available for use via the number. Which is great! The gdm-session-worker would call a special DBus API to pass along the FD into the main GDM process, and the main GDM process will ultimately pass the FD into gnome-shell.

Once gnome-shell recieves the FD, all it has to do is add it to the main loop (i.e. `poll` it) and start reading from the FD to recieve events.

Now, for the duration of the conversation PAM will be blocking and waiting for a response. The request that sent over the FD was, in PAM's view, a question. So the answer must come from the frontend before anything else can happen. Of course the authentication is happening out of band. Once the frontend decides that it's done with authentication (i.e. if it has a fatal `authenticationFailed` reponse, or `authenticationSuccessful`), then it can send an empty PAM "answer" to the "question". PAM then takes back over, and either returns a PAM error or continues and allows the gdm-session-worker to start a session.



## Startup

The protocol begins with a set sequence of events, which follows. First the authenticator sends:

```js
{
    "event": "hello",
    "version": 1,
}
```

If the version is unsupported, the frontend should just close the socket and then send PAM an empty answer so that PAM can take over. Since there hasn't yet been an `authenticationSuccessful` event, PAM will return a failure.

If the version is supported, the frontend reponds:

```js
{
    "event": "hello",
    "supportedMechanisms": [ ... ],
    "supportedAuthFailureReasons": [ ... ],
}
```

This communicates the frontend's capabilities to the authenticator. Mechanisms and authentication failure reasons are documented below.

In response to this information, the authenticator responds with a series of "flows". A flow is a sequence of mechanisms. Most commonly, a flow would correspond 1:1 to some mechanism (i.e. the `password` mechanism). However, flows can be more complicated: for instance, your enterprise might want to define a flow that first prompts for a `password`, then does `eidp` SSO login, and finally prompts for an `otp`. 

Flows exist to give the user a choice of how they want to log in. The frontend will present a list of flows to the user, and the user can select whichever flow they want to attempt authentication with. Most commonly, this will be basic stuff: does the user want to log in via "Password" or "Pin" or "Smartcard". But again, flows are flexible enough that they can represent more complicated sequences.

Flows are communicated as follows:

```js
{
    "event": "flows",
    "flows": [
        { // This is a single flow
            "id": "mycorp-login-flow",
            "primaryMechanism": "eidp",
            "name": "MyCorp Login",
        },
        ... // There can be more flows that follow
    ]
}
```

The authenticator gives the frontend an ordered list of flows. The flows are ordered in "most-recommended" order (as chosen by the authenticator), so if the frontend needs to pick a flow to start by default it should pick the first flow in the list.

Each flow has an ID, which is stable between authentication attempts. This allows the protocol to refer to any specific flow. The frontend can use this ID to remember which flow the user prefers to use. The IDs will be unique for any given user.

The rest of the flow's information is for display purposes _only_. The flow's `primaryMechanism` is used to determine how the flow will be presented to the user: which icons to use, and which name to display (including localization). This makes basic flows very convenient: just send `{ "id": "password", "primaryMechanism": "password" }` and the frontend will take care of displaying the flow optimally to the user. However, for more custom use-cases where you have some custom flow, the flow may also contain a `name` that will override the name selected via `primaryMechanism`. Note that the flow is not limited to only using the `primaryMechanism`.

The frontend will either prompt the user to select a flow, or pre-select a flow for the user. Once a flow is selected, the frontend communicates this to the authenticator:

```js
{
    "event": "start",
    "flow": "mycorp-login-flow",
}
```

From this point forward, the protocol becomes a lot more event-driven. The authenticator will start sending events that request the display of certain UI components, and the frontend communicates the user's input back to the authenticator.

The frontend may want to restart a flow (i.e. if the user hits the "back" button) or switch flows (i.e. if the user selects a different flow from a menu). Both can be achieved by sending the `start` event a second time with the cooresponding flow ID.

## Authentication Mechanisms and Conversation

Authentication mechanisms are standardized UI patterns that an authenticator can request from a frontend. For instance: if the authenticator asks the frontend for a password, the frontend will pick an appropriate UI for password entry. Mechanisms can be categorized as "primary" or "secondary". There can only be one primary mechanism active (i.e. visible on screen) at a time, so if the authenticator asks to show a different primary mechanism the previous UI should be replaced with the new one. Secondary mechanisms can co-exist with the primary mechanism and with each-other

Once a flow is started, the authentication "conversation" begins. At a high level, a conversation looks like the following:

1. The authenticator requests a primary authentication mechanism from the frontend
2. The frontend displays the appropriate UI for this authentication mechanism
3. The user interacts with the UI to give it some data (types in a password, touches a fingerprint sensor, etc)
4. Once the user is finished, the frontend sends the user's entered data to the authenticator
5. If the user has failed to authenticate, or if there are no more steps left in the flow, the authenticator ends the conversation and returns success or failure
6. Otherwise, the authenticator continues with the next step of the flow. Return to step 1

Note that the use of this protocol encapuslates one authentication attempt. A flow might have multiple steps in it (i.e. "password" followed by "otp"), and the authenticator's ability to switch primary authentication mechansims is designed just for that. The authenticator should not handle a primary authentication method's failure on its own. For example: if the user enters an incorrect password, the authenticator should not prompt for a second attempt. Instead, it should emit the `authenticationFailed` event and terminate the conversation. Conversely, the authenticator _is_ expected to handle secondary authentication method failures on its own, because these are not fatal to the overall login attempt.

Each authentication mechanism is started via an event that the authenticator sends. The following is a description of each such event and what the frontend should do in response:

- `password`: A generic password box
    - This method is always a primary method
    - Arguments (data that the authenticator includes with the event it sends to the frontend):
        - `overridePrompt`: Overrides the default prompt in the password entry box. Optional. Should only be used if absolutely necessary
    - Response: frontend emits the `response` event with the following arguments:
        - `password`: The password entered by the user

- `text`: Arbitrary text input
    - This method is always primary
    - Arguments:
        - `prompt`: The prompt to put in the text box. Required
    - Response: `response` event with arguments:
        - `text`: The text entered by the user

- `newPassword`: UI for choosing a new password
    - The frontend prompts for the user to enter a new password twice, and only responds once the two instances of the new password match.
    - The frontend should use libpwquality to enforce the system-wide password quality policy before responding with the new password
    - This method is always primary
    - Arguments:
        - `reason`: The reason that the user is being prompted to pick a new password. Options:
            - `unset`: The user doesn't have a password set yet, so we're setting one now
            - `expired`: The user's previous password has expired
            - `custom`: Just always display the `fallbackMessage`
        - `fallbackMessage`: The message to display if the UI doesn't know how to handle the `reason`
    - Response: `response` event with arguments:
        - `newPassword`: The user's new password

- `pin`: UI for entering a numeric PIN code
    - This method is always primary
    - Arguments:
        - `length`: The number of digits in the PIN code
        - `overridePrompt`: Overrides the default prompt (or, more likely, adds a prompt) to the PIN entry UI. Optional. Should only be used if absolutely necessary
    - Response: `reponse` event with arguments:
        - `pin`: The PIN code entered by the user

- `otp`: UI for entering a one-time-password
    - This method is always primary
    - Arguments:
        - `alphanumeric`: Allow alphabetic characters in the OTP. Defaults to false
        - `length`: The number of digits/characters in the OTP
        - `prefix`: Some OTPs start with a prefix (e.g. Google likes to use `G-######` as their format). Defaults to empty
        - `suffix`: Similar to `prefix`, but for a suffix instead
        - `overridePrompt`: Overrides the default prompt (or, more likely, adds a prompt) to the OTP entry UI. Optional. Should only be used if absolutely necessary
    - Response: `response` event with arguments:
        - `otp`: The OTP entered by the user. Neither the prefix nor the suffix are included.

- `chooser`: UI for choosing from a list of options
    - This method is always primary
    - Arguments:
        - `prompt`: A string to display to the user, explaining what they're choosing between. Optional.
        - `options`: An array of objects that describes the options that the user can select between. Each object in the array has the following keys:
            - `key`: The machine-usable string that identifies this option
            - `name`: The display name for this option, to be presented to the user
    - Response: `response` event with arguments:
        - `selection`: The selected option's `key`

- `eidp`: Web-based SSO login
    - The frontend displays a QR code and/or an embedded web browser that loads a web page for single-sign-on
    - This method is always primary
    - Arguments:
        - `url`: The URL of the SSO login page. The QR code encodes this URL, and the web browser navigates to the URL.
        - `displayUrl`: A simplified URL to display to the user in text, suitible for the user to type manually. Optional
        - `code`: A short code that is displayed to the user along with the `displayUrl`. This allows the user to complete authentication from an alternative device (like their phone)
        - `showDone`: If true, the authenticator is unable to detect on its own when authentication has succeeded and the frontend should have a "Done" button for the user to press when they are done
        - `embedded`: Allow the use of an embedded web view directly on the login screen. Defaults to true
        - `external`: Allow the use of a QR code, for logging in via an external device (such as a phone). Defaults to true. 
    - Response:
        - if `showDone` is true, the frontend emits a `response` event (with no arguments) when the user clicks the done button
        - if `showDone` is false, the frontend doesn't need to respond. The authenticator will continue with the conversation on its own

- `fingerprint`: Fingerprint authentication
    - The frontend prompts for the user to touch their fingerprint to the sensor, then listens for additional events (documented below) that the authenticator emits to communicate updates about fingerprint sensor state
    - This method is either primary or secondary
    - Arguments:
        - `primary`: When true, this is a primary authentication mechanism
        - `swipe`: When true, the fingerprint sensor requires a swiping motion of the finger, rather than a touch. Defaults to false
    - Response: No response is necessary. The authenticator will continue with the conversation on its own

- `face`: Facial recognition
    - The frontend prompts for the user to show their face to the sensor, and listens for additional events (documented below) that the authenticator emits to communicate updates about facial recognition state
    - This method is either primary or secondary
    - Arguments:
        - `primary`: When true, this is a primary authentication mechanism
    - Response: No response is necessary. The authenticator will continue with the conversation on its own

- `monitorPasskey`: Prompt the user to insert a FIDO security token
    - The frontend monitors for a FIDO security token to be inserted and prompts for the user to insert a FIDO security token
    - If a FIDO token is already inserted, the frontend responds immediately
    - This method is either primary or secondary
    - A frontend shouldn't advertise support for this mechanism in `supportedMechanisms`; support is implied for any frontend that supports the `passkey` mechanism.
    - Arguments:
        - `primary`: When true, this is a primary authentication mechanism
        - `name`: Display name of the security token to insert. Optional. For example, if an enterprise deploys only Yubikeys, it might be helpful for the end-user if the prompt asks them to insert their "Yubikey" rather than a generic "Insert security token" message.
    - Response: frontend emits the `passkeyInserted` event when a passkey is inserted

- `passkey`: FIDO security token handling
    - The frontend prompts the user for a "pin" (which is actually an alphanumeric password)
    - _After_ the frontend sends the response, the UI should prompt the user to touch their FIDO token
    - The frontend shall continue monitoring for FIDO token insertion/removal events
    - This method is always primary
    - Arguments:
        - `remainingAttempts`: The number of remaining attempts for the FIDO PIN until the device is locked
    - Response:
        - if the user has confirmed their entered pin code, then the frontend prompts the user to touch the FIDO token and emits a `response` event with the following arguments:
            - `pin`: The user's entered pin code
        - if the FIDO token is removed before the user is done interacting with the UI, the frontend emits a `passkeyRemoved` event
        - Once the user touches the FIDO token, the authenticator will continue the converstaion on its own

- `monitorSmartcard`: Prompt for the user to insert a smartcard
    - The frontend monitors for smartcard insertion events, and prompts for the user to insert a smartcard
    - If a smarcard is already inserted, the frontend responds immediately
    - This method is either primary or secondary
    - A frontend shouldn't advertise support for this mechanism in `supportedMechanisms`; support is implied for any frontend that supports the `smartcard` mechanism.
    - Arguments:
        - `primary`: When true, this is a primary authentication mechanism
    - Response: frontend emits the `smartcardInserted` event when a smartcard is inserted

- `smartcard`: Smart card handling
    - Smartcards might have more than one certificate available. If this card has more than one certificate, the frontend first prompts the user to pick a certificate
    - Next, the frontend prompts the user for a "pin" (which is actually an alphanumeric password)
    - The frontend shall continue monitoring for smartcard insertion/removal events
    - This method is always primary
    - Arguments:
        - `certificates`: An array of objects that describe the available certificates that the user can select between. Each object in the array has the following keys:
            - `id`: The machine-usable string that identifies this certificate
            - `slotName`: A display name for the PIV slot of this certificate. Example: "Certificate for PIV Authentication"
            - `commonName`: The `CN` field of the certificate. Example: "John"
            - `organization`: The `O` field of the certificate. Example: "Red Hat"
            - TODO: Do we have the slot available in non-display-name-form? Are there other fields from the certificate that we should expose?
    - Response:
        - if the user has confirmed their entered pin code, then the frontend emits a `response` event with the following arguments:
            - `pin`: The user's entered pin code
            - `certificate`: The `id` of the certificate that the user selected. Required if `certificates` has more than one option
        - if the smartcard is removed before the user is done interacting with the UI, the frontend emits a `smartcardRemoved` event

## Other events

While the primary conversation is occuring as described above, some additional events may occur. This section of the document explains these different events.

#### General authentication status

These events might be emitted while any mechanism is active:

- `authenticationFailed`: The primary authentication mechanism has failed
    - Sent from authenticator to frontend
    - This ends the authentication conversation and terminates this protocol entirely
    - Arguments:
        - `reason`: The reason that authentication failed. The frontend lists these in `supportedAuthFailureReasons`. Each type of reason might add additional arguments to the event. Valid reasons follow:
            - `incorrect`: The user has input the incorrect password/pin/pattern, or biometrics didn't match, or the authentication challenge has been failed in some other "obvious" way
            - `accountLocked`: The user's account has been locked by an administrator. Adds the following arguments to the event:
                - `instructions`: User-visible string explaining what to do next: where to call / email / go. Optional. Examples:
                    - "Call Corporate HR: +1 (800) 555 1234"
                    - "Email jsmith@example.com"
                    - "Go to Building C, Office 1234"
            - `antiBruteFource`: The user's account has been temporarily locked as an anti-brute-forcing measure. Adds the following arguments to the event:
                - `until`: A timestamp of when the account will get unlocked
                - `attempts`: The number of failed login attempts in a row
            - `custom`: Just use the `fallbackMessage`
        - `fallbackMessage`: Fallback string to show in the UI if it doesn't support the provided reason
        - `remainingAttempts`: How many attempts are remaining before account gets locked / anti-brute-force kicks in. Optional. If unset, there's no limit.
    - Response: the frontend should return control back to PAM, which will return failure. Then the frontend can retry / start over

- `authenticationSuccessful`: Authentication has succeeded
    - Sent from authenticator to frontend
    - This is emitted by _both_ primary and secondary mechanisms!
    - This ends the authentication conversation and terminates this protocol entirely
    - Arguments: none
    - Response: the frontend should return control back to PAM, which will return success. The frontend can then continue to start/unlock the user's session

- `start`: Start a new conversation for a new flow (possibly aborting an existing flow)
    - Sent from frontend to authenticator
    - The frontend emits this whenever the user hits the "back" button, or whenever the user changes their preferred flow in the UI
    - The frontend should stop all of its mechanisms (including secondary mechanisms) whenever it requests the start of a new flow
    - Arguments:
        - `flow`: The flow to start. It's perfectly valid for this to be the same as the flow that's currently active
    - Response: The authenticator starts the conversation and sends a primary authentication mechanism

- `flowChanged`: Notifies the frontend that the authenticator has changed the user's flow
    - Send from the authenticator to the frontend
    - The frontend should act as if the user has selected a new flow from the menu, except it should NOT emit a `start` event and should NOT interrupt any mechanisms
    - The frontend should update the user's remembered preferred flow
    - Arguments:
        - `flow`: The flow to change to
    - Response: None

#### Password change events

These events might be emitted while the `newPassword` mechanism is active:

- `newPasswordRejected`: The new password has failed for some reason. Try again
    - Sent from authenticator to frontend
    - The frontend should notify the user that the new password has been rejected and that they should pick a different password. The `newPassword` mechanism should remain active
    - Arguments:
        - `reason`: The reason that the new password was rejected. Valid reasons follow:
            - `custom`: Just use the `fallbackMessage`
        - `fallbackMessage`: Fallback string to show in the UI if it doesn't support the provided reason
    - Response: none. The `newPassword` mechanism will eventually emit a `response` as usual.

#### Fingerprint events

These events might be emitted while the `fingerprint` mechanism is active:

- `fingerprintFeedback`: The fingerprint scanner is operational and has some feedback to report to the user
    - Sent from authenticator to frontend
    - The frontend should react by indicating to the user what is happening or what the user should do (i.e. by playing an animation, or giving written instructions)
    - Arguments:
        - `feedback`: The feedback to provide to the user. Valid values follow:
            - `scanning`: The fingerprint sensor has detected a finger and is working to scan it
            - `swipeTooSlow`: The user swiped across the sensor too slowly and needs to speed up
            - `swipeTooFast`: The user swiped across the sensor too quickly and needs to slow down
            - `morePressure`: The user isn't applying enough pressure on the fingerprint sensor
            - `moveLeft`: The user should move their finger a little to the left to center it on the sensor
            - `moveRight`, `moveUp`, `moveDown`: Like `moveLeft`, but for the other directions
            - `recenter`: The user's finger is not centered on the sensor, but we don't have specific directional instructions available
            - `cancelled`: The user has removed their finger from the fingerprint sensor before the scan could complete
            - Unknown values should be treated as equivalent to `scanning`
    - Response: none

- `fingerprintFailed`: The fingerprint sensor has scanned the finger and determined that it doesn't match
    - Sent from authenticator to frontend
    - This is sent only while the `fingerprint` mechanism is secondary. If it's primary, `authenticationFailed` will be sent instead
    - Arguments:
        - `retryAllowed`: If true, the user can try to use the fingerprint sensor again and the `fingerprint` mechanism remains active. Otherwise, the fingerprint sensor is disabled.
    - Response: none

#### Facial recognition events

These events might be emitted while the `face` mechanism is active:

- `faceFeedback`: The facial recognition system is operational and has some feedback to report to the user
    - Sent from authenticator to frontend
    - The frontend should react by indicating to the user what is happening or what the user should do (i.e. by playing an animation, or giving written instructions)
    - Arguments:
        - `feedback`: The feedback to provide to the user. Valid values follow:
            - `scanning`: The facial recognition system sees a face and is attempting to scan it
            - `moveCloser`: The user needs to move closer to the camera
            - `moveFurther`: The user needs to move further from the camera
            - `recenter`: The user needs to ensure that they're facing and centered on the camera
            - `blink`: Ask the user to blink, as a liveness check
            - `lost`: The facial recognition system has lost sight of the user's face
            - Unknown values should be treated as equivalent to `scanning`
    - Response: none

- `faceFailed`: The facial recognition system has scanned the face and determined that it does not match
    - Sent from authenticator to frontend
    - This is sent only while the `face` mechanism is secondary. If it's primary, `authenticationFailed` will be sent instead
    - Arguments:
        - `retrying`: If true, the facial recognition system will keep trying to scan the next face it sees and the `face` mechanism remains active. Otherwise, facial recognition is disabled
    - Response: none

#### Passkey events

These events might be emitted while the `passkey` or `monitorPasskey` mechanisms are active:

- `passkeyInserted`: A FIDO security token has been inserted
    - Sent from frontend to authenticator
    - Arguments: none
    - Response: the authenticator should start the `passkey` mechanism
        - If the authenticator has a flow dedicated to passkeys, then it should also emit the `flowChanged` event to notify the frontend that we've entered the passkey flow

- `passkeyRemoved`: The FIDO security token has been removed
    - Sent from frontend to authenticator
    - Arguments: none
    - Response: the authenticator can start the `monitorPasskey` mechanism:
        - If the authenticator has a flow dedicated to passkeys and `flowChanged` has been emitted, the `monitorPasskey` mechanism should be the primary mechanism
        - Otherwise, the `monitorPasskey` mechanism should be secondary, and the authenticator should pick a different appropriate primary mechanism

#### Smart card events

These events might be emitted while the `smartcard` or `monitorSmartcard` mechanisms are active:

- `smartcardInserted`: A smart card has been inserted
    - Sent from frontend to authenticator
    - Arguments: none
    - Response: the authenticator should read the smart card for a list of certificates, then start the `smartcard` mechanism
        - If the authenticator has a flow dedicated to smart cards, then it should also emit the `flowChanged` event to notify the frontend that we've entered the smart card flow

- `smartcardRemoved`: The smart card has been removed
    - Sent from frontend to authenticator
    - Arguments: none
    - Response: the authenticator can start the `monitorSmartcard` mechanism:
        - If the authenticator has a flow dedicated to smart cards and `flowChanged` has been emitted, the `monitorSmartcard` mechanism should be the primary mechanism
        - Otherwise, the `monitorSmartcard` mechanism should be secondary, and the authenticator should pick a different appropriate primary mechanism
