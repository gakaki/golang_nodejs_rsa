const NodeRSA = require('node-rsa');
const fs = require('fs')

/**
 * @typedef KeyPair 
 * @property {string} publicKey 
 * @property {string} privateKey 
 **/

/**
 * @typedef GenerateOptions 
 * @property {number} [bits] default 2048
 **/

/**
 * 
 * @param {GenerateOptions} [options]
 * @return {KeyPair} 
 */
const generateKeyPair = function(options) {
    if (!options) options = {};
    if (!options.bits) options.bits = 2048; // 4096;
    var key = new NodeRSA({ b: options.bits });

    const privateKeyPem = key.exportKey('private');
    const publicKeyPem = key.exportKey('public');
    return { privateKey: privateKeyPem, publicKey: publicKeyPem };
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function sign(data, privateKey) {
    var key = new NodeRSA(privateKey, 'private');
    return key.sign(data, 'hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} signature 
 * @param {string} publicKey 
 * @return {boolean}
 */
function verify(data, signature, publicKey) {
    var key = new NodeRSA(publicKey, 'public');
    return key.verify(data, signature, undefined, 'hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} publicKey 
 * @return {string}
 */
function encrypt(data, publicKey) {
    var key = new NodeRSA(publicKey, 'public');
    return key.encrypt(data, 'buffer').toString('hex');
}

/**
 * 
 * @param {string} data 
 * @param {string} privateKey 
 * @return {string}
 */
function decrypt(data, privateKey) {
    var key = new NodeRSA(privateKey, 'private');
    return key.decrypt(Buffer.from(data, 'hex')).toString();
}

const aliceKeyPair = generateKeyPair({ bits: 2048 });
console.log(aliceKeyPair.privateKey)
fs.writeFileSync('./private.key', aliceKeyPair.privateKey);
console.log(aliceKeyPair.publicKey)
fs.writeFileSync('./public.key', aliceKeyPair.publicKey);


const message = 'SHDR-ORDER-NO-123456';
const encryptedMessage = encrypt(message, aliceKeyPair.publicKey);
const decryptedMessage = decrypt(encryptedMessage, aliceKeyPair.privateKey);
console.assert(message === decryptedMessage, 'encrypt decrypted should be the same');

const signature = sign(message, aliceKeyPair.privateKey);
console.log({ message })
console.log('signature', signature);


console.log("---------------")

const isSignedVerifyOk = verify(message, signature, aliceKeyPair.publicKey)
console.assert(isSignedVerifyOk, 'invalid signature');
console.log("验签应该为true才对",isSignedVerifyOk)


const isSignedVerifyFalse = !verify(message + 'f', signature, aliceKeyPair.publicKey)
console.log("验签应该为false才对",isSignedVerifyFalse)
console.assert(isSignedVerifyFalse, 'invalid signature');

