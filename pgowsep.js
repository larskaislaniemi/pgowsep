window.pgp_STATE = {
    privateKey: undefined,
    publicKey: undefined,
    revocationKey: undefined,
    theirKeys: [],
    ui_theirKeysListEl: undefined,
    settings: {},
}

window.pgp_STATE.setKey = function(priv, pub, rev) {
    let s = window.pgp_STATE;

    if (priv) {
        s.privateKey = priv;
    } else s.privateKey = undefined;

    if (pub) s.publicKey = pub;
    else if (s.privateKey) s.publicKey = s.privateKey.toPublic();
    else s.publicKey = undefined;

    if (rev) s.revocationKey = rev;
    else s.revocationKey = undefined;

    let el_keyIdText = document.getElementById('uiMyKey').querySelector("#uiLabelMyKeyId");
    if (s.privateKey) el_keyIdText.innerText = s.privateKey.getUserIDs();
    else if (s.publicKey) el_keyIdText.innerText = s.publicKey.getUserIDs();
    else el_keyIdText.innerText = '[no user ID]';

    if (s.privateKey && s.publicKey) {
        document.getElementById('uiMyKey').querySelector("#uiLabelMyKeyStatus").innerText = 'Private and public key loaded';
        const el_link = document.createElement('A');
        const resURL = window.URL.createObjectURL(new Blob([s.publicKey.armor()], { type: "text/plain" }));
        el_link.href = resURL;
        el_link.download = s.publicKey.getUserIDs() + ".pub.asc";
        el_link.innerText = 'Download public key';
        document.getElementById('uiMyKey').querySelector("#uiLabelMyKeyStatus").appendChild(el_link);
     } else if (s.privateKey) {
        document.getElementById('uiMyKey').querySelector("#uiLabelMyKeyStatus").innerText = 'Private key loaded';
    } else if (s.publicKey) {
        document.getElementById('uiMyKey').querySelector("#uiLabelMyKeyStatus").innerText = 'Public key loaded';
    }
}

function domClearNodes(el, first = true) {
    while (el.lastChild) domClearNodes(el.lastChild, false);
    if (!first) el.parentNode.removeChild(el);
}

window.pgp_STATE.refreshUITheirKeys = function() {
    let s = window.pgp_STATE;

    if (!s.ui_theirKeysListEl) return;
   
    domClearNodes(s.ui_theirKeysListEl);

    for (let i = s.theirKeys.length-1; i >= 0; i--) {
        try {
            s.theirKeys[i].toPublic();
        } catch {
            alert("Key " + s.theirKeys[i].getUserIDs() + " is not a private/public key");
            s.theirKeys.splice(i, 1);
            continue;
        }
        
        let el_key = document.createElement('LI');
        el_key.innerText = s.theirKeys[i].getUserIDs();
        if (el_key.innerText.length <= 0) el_key.innerText = '[no user ID]';
        let el_remove = document.createElement('A');
        el_remove.innerText = '[X]';
        el_remove.href = '#';
        el_remove.pgp_keyIndex = i;
        el_key.appendChild(el_remove);
        s.ui_theirKeysListEl.appendChild(el_key);

        el_remove.addEventListener('click', (evt) => {
            window.pgp_STATE.removeTheirKey(i);
        });
    }
}

window.pgp_STATE.removeTheirKey = function(idx) {
    let s = window.pgp_STATE;

    s.theirKeys.splice(idx, 1);
    s.refreshUITheirKeys();
}

window.pgp_STATE.addTheirKey = function(key) {
    let s = window.pgp_STATE;

    for (const exkey of s.theirKeys) {
        if (exkey.getFingerprint() == key.getFingerprint()) return;
    } 
    
    s.theirKeys.push(key);

    s.refreshUITheirKeys();
}

function makeLoadKeyFunction(keytype, actionFnc) {
    let keyReaderFnc;
    if (keytype == 'private') keyReaderFnc = openpgp.readPrivateKey;
    else if (keytype == 'public') keyReaderFnc = openpgp.readKey;
    else throw new Error('Invalid parameter value for keytype');

    return function(evt) {
        if (!evt.target.files.length) {
            alert("No files selected");
            return;
        }
    
        let reader = new FileReader();
        reader.onloadend = async function(evt) {
            let key = undefined;
    
            try {
                key = await keyReaderFnc({ binaryKey: new Uint8Array(this.result) });
            } catch (err) {
                console.warn("Reading as binary key failed");
            }
    
            if (!key) {
                try {
                    key = await keyReaderFnc({ armoredKey: (new TextDecoder()).decode(this.result) });
                } catch (err) {
                    console.warn("Reading as armored key failed");
                }
            }
    
            if (!key) {
                alert('Failed to load key');
                return;
            }
    
            actionFnc(key);
        }
        reader.readAsArrayBuffer(evt.target.files[0]);
        evt.target.value = null;
    }
}

function generateKey(evt) {
    let passphrase_used = undefined;

    const el_pgp_name = document.getElementById('inputGenerateKey_name');
    const el_pgp_email = document.getElementById('inputGenerateKey_email');
    const el_pgp_passphrase1 = document.getElementById('inputGenerateKey_passphrase1');
    const el_pgp_passphrase2 = document.getElementById('inputGenerateKey_passphrase2');
    const pgp_name = el_pgp_name.value;
    const pgp_email = el_pgp_email.value;
    const pgp_passphrase1 = el_pgp_passphrase1.value;
    const pgp_passphrase2 = el_pgp_passphrase2.value;

    const el_textGeneratedKey = document.getElementById('textGeneratedKey');
    const el_useGeneratedKey = document.getElementById('useGeneratedKey');
    const el_downloadPrivateKey = document.getElementById('linkPrivateKey');
    const el_downloadPublicKey = document.getElementById('linkPublicKey');
    const el_downloadRevocationKey = document.getElementById('linkRevocationKey');

    if (pgp_passphrase1 != pgp_passphrase2) {
        alert("Passphrases do not match");
        return;
    } else if (pgp_passphrase1 != '') {
        passphrase_used = pgp_passphrase1;
    } else {
        passphrase_used = undefined;
    }

    if (el_downloadPrivateKey['pgp_isUnSaved'] ||
        el_downloadRevocationKey['pgp_isUnSaved']) {
        let res = confirm("Previously generated private and/or revocation key not saved, are you sure?");
        if (!res) return;
    }

    openpgp.generateKey({
        type: 'curve25519', 
        userIDs: [{ name: pgp_name, email: pgp_email }], 
        passphrase: passphrase_used, 
        format: 'object',
        type: 'ecc',
    }).then((res) => {
        let createLink = function(data, el_id, filename, type) {
            const privKeyUrl = window.URL.createObjectURL(new Blob([data], { type: "text/plain" }));
            el_id.href = privKeyUrl;
            el_id.download = filename;
            el_id.innerText = 'Download '+ type + ' key';
            el_id['pgp_isUnSaved'] = true;
            el_id.addEventListener('click', (evt) => { evt.target['pgp_isUnSaved'] = false; })
        }

        el_textGeneratedKey.innerText = 'Key generated: ' + res.privateKey.getUserIDs();
        el_useGeneratedKey.innerText = 'Use this key now';
        el_useGeneratedKey.href = '#';
        el_useGeneratedKey.addEventListener('click', (evt) => {
            window.pgp_STATE.setKey(res.privateKey, res.publicKey, res.revocationCertificate);
        });

        // TODO: export in binary if set in settings (privateKey.write())
        if (window.pgp_STATE.settings['settingsArmoredOutput'] == true) {
            createLink(res.privateKey.armor(), el_downloadPrivateKey, pgp_email + '.private.asc', 'private');
            createLink(res.publicKey.armor(), el_downloadPublicKey, pgp_email + '.public.asc', 'public');
            createLink(res.revocationCertificate, el_downloadRevocationKey, pgp_email + '.revocation.asc', 'revocation');
        } else {
            createLink(res.privateKey.write(), el_downloadPrivateKey, pgp_email + '.private.bin', 'private');
            createLink(res.publicKey.write(), el_downloadPublicKey, pgp_email + '.public.bin', 'public');
            createLink(res.revocationCertificate, el_downloadRevocationKey, pgp_email + '.revocation.asc', 'revocation');
        }

        el_pgp_passphrase2.value = el_pgp_passphrase1.value = el_pgp_email.value = el_pgp_name.value = '';

        //alert("Key generated.");
        
    }, (error) => {
        alert("Key generation failed");
        console.error(error);
    });
}

async function doDecrypt(evt) {
    let el_file = document.getElementById('buttonLoadInputFile');

    if (!el_file?.files.length) {
        alert("No files selected");
        return;
    }

    if (!window.pgp_STATE.privateKey) {
        alert("No private key defined!");
        return;
    }

    let key = undefined
    if (window.pgp_STATE.privateKey.isDecrypted()) key = window.pgp_STATE.privateKey;
    else {
        let passphrase = prompt('Passphrase?');
        try {
            key = await openpgp.decryptKey({
                privateKey: key,
                passphrase: passphrase,
            });
        } catch (err) {
            console.log(err);
        }
    }

    if (!key?.isDecrypted()) {
        alert('Private key not decrypted - wrong passphrase?');
        return;
    }

    let reader = new FileReader();
    reader.onloadend = async function(evt) {
        const decoder = new TextDecoder();
        const str = decoder.decode(this.result);

        let outfmt;
        if (window.pgp_STATE.settings.settingsArmoredOutput) outfmt = 'utf8';
        else outfmt = 'binary';

        let msg = undefined;
        let retry = false;
        try {
            msg = await openpgp.readMessage({
                armoredMessage: str,
            });
        } catch (err) {
            console.log(err);
            retry = true;
        }

        if (retry) {
            retry = false;
            try {
                msg = await openpgp.readMessage({
                    binaryMessage: new Uint8Array(this.result),
                });
            } catch (err) {
                console.log(err);
                retry = true;
            }
        }

        if (retry) {
            alert("Failed to read encrypted message!");
            return;
        }

        let encmsg;
        try {
            encmsg = await openpgp.decrypt({
                message: msg,
                decryptionKeys: key,
                verificationKeys: window.pgp_STATE.privateKey,
                format: outfmt,
            });
        } catch (err) {
            console.log(err);
            alert("Failed to decrypt the message!");
            return;
        }
        
        const el_link = document.getElementById('linkResultFile');
        const resURL = window.URL.createObjectURL(new Blob([encmsg.data], { type: "text/plain" }));
        el_link.href = resURL;
        el_link.download = encmsg.filename;
        el_link.click();
    }
    reader.readAsArrayBuffer(el_file.files[0]);
}

async function doEncrypt(evt) {
    let el_file = document.getElementById('buttonLoadInputFile');

    if (!el_file?.files.length) {
        alert("No files selected");
        return;
    }

    if (window.pgp_STATE.theirKeys.length <= 0) {
        alert("No recipients defined!");
        return;
    }

    let key = undefined;

    if (window.pgp_STATE.privateKey?.isDecrypted()) key = window.pgp_STATE.privateKey;
    else if (window.pgp_STATE.privateKey) {
        let passphrase = prompt('Passphrase?');
        try {
            key = await openpgp.decryptKey({
                privateKey: key,
                passphrase: passphrase,
            });
        } catch (err) {
            console.error(err);
        }
    }

    if (key && !key.isDecrypted()) {
        alert('Private key not decrypted - wrong passphrase?');
        return;
    }

    let reader = new FileReader();
    reader.onloadend = async function(evt) {

        let msg = await openpgp.createMessage({ 
            binary: new Uint8Array(this.result), 
            filename: el_file.files[0].name,
            format: 'binary',
        });

        let fmt;
        if (window.pgp_STATE.settings.settingsArmoredOutput) fmt = 'armored';
        else fmt = 'binary';

        let encmsg = await openpgp.encrypt({
            message: msg,
            encryptionKeys: window.pgp_STATE.theirKeys,
            signingKeys: key,
            format: fmt,
        });

        const el_link = document.getElementById('linkResultFile');
        const resURL = window.URL.createObjectURL(new Blob([encmsg], { type: "text/plain" }));
        el_link.href = resURL;
        if (fmt == 'armored') el_link.download = el_file.files[0].name + ".asc";
        else el_link.download = el_file.files[0].name + ".bin";
        el_link.click();
    }
    reader.readAsArrayBuffer(el_file.files[0]);
}

window.pgp_STATE.ui_theirKeysListEl = document.getElementById('uiListTheirKeys');
document.getElementById('buttonGenerateKey').addEventListener('click', generateKey);
document.getElementById('buttonLoadKey').addEventListener('change', makeLoadKeyFunction('private', window.pgp_STATE.setKey));
document.getElementById('buttonLoadTheirKey').addEventListener('change', makeLoadKeyFunction('public', window.pgp_STATE.addTheirKey));
document.getElementById('buttonEncrypt').addEventListener('click', doEncrypt);
document.getElementById('buttonDecrypt').addEventListener('click', doDecrypt);

for (el_setting of document.getElementById('uiSettings').querySelectorAll('input[type=checkbox]')) {
    window.pgp_STATE.settings[el_setting.id] = el_setting.checked;
    el_setting.addEventListener('change', (evt) => {
        window.pgp_STATE.settings[evt.target.id] = evt.target.checked;
    });
}




