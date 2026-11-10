import {
  createPrivateKey,
  createPublicKey,
  publicEncrypt,
  createECDH,
  privateDecrypt,
  sign,
  verify,
  diffieHellman,
  constants
} from "node:crypto";

const ED25519 = 6;
const ED448 = 7;
const X25519 = 4;
const X448 = 5;

const P_256 = 1;
const SECP256K1 = 8;
const P_384 = 2;
const P_521 = 3;

const ES256 = -7;
const ES256K = -47;
const ES384 = -35;
const ES512 = -36;

const PS512 = -39;
const PS384 = -38;
const PS256 = -37;

const RSA_OAEP_1 = -40;
const RSA_OAEP_256 = -41;
const RSA_OAEP_512 = -42;

function getAlg(alg) {
  switch(alg) {
    case ES256:
    case ES256K: 
    case PS256:
    case RSA_OAEP_256:
      return "sha256";
    case ES384:
    case PS384: 
      return "sha384";
    case ES512: 
    case PS512: 
    case RSA_OAEP_512:
      return "sha512";
    case RSA_OAEP_1:
      return "sha1";
    default:
      throw "Invalid alg"
  }

}

function getCurve(crv) {
  switch(crv) {
    case P_256:
      return "prime256v1";
    case SECP256K1: 
      return "secp256k1";
    case P_384:
      return "secp384r1";
    case P_521: 
      return "secp521r1";
    case ED25519:
      return "ed25519";
    case ED448: 
      return "ed448"
    case X448: 
      return "x448";
    case X25519:
      return "x25519";
    default:
      throw "Invalid curve"
  }

}

export function ecdhDerive(crv, key_rec, key_send) {
  let private_send;
  let publicKey_rec;
  let curve = getCurve(crv);

  if (crv === X448 || crv === X25519) {
    try {
      private_send = createPrivateKey({
        key: key_send,
        format: "raw-private",
        asymmetricKeyType: curve,
      });

      publicKey_rec = createPublicKey ({
        key: key_rec,
        format: "raw-public",
        asymmetricKeyType: curve,
      });
    } catch {
      throw "Invalid ECDH key";
    }

    try {
      return diffieHellman({
        privateKey: private_send,
        publicKey: publicKey_rec
      });
    } catch {
      throw "ECDH derive error";
    }
  }

  const ecdh = createECDH(curve);
  try {
    ecdh.setPrivateKey(key_send);
  } catch {
    throw "Invalid ECDH private key";
  }

  try {
    return ecdh.computeSecret(key_rec);
  } catch {
    throw "ECDH derive error";
  }
}
export function ecdsaSign(key, content, alg, crv) {
  let privateKey;
  let digest_alg = getAlg(alg);
  let curve = getCurve(crv);

  try {
    privateKey = createPrivateKey({
      key: key,
      format: "raw-private",
      asymmetricKeyType: "ec",
      namedCurve: curve,
    });
  } catch {
    throw "Invalid ECDSA private key";
  }

  try {
    return sign(
      digest_alg,
      content,
      { key: privateKey, dsaEncoding: "ieee-p1363"}
    );
  } catch {
    throw "ECDSA sign error";
  }
}

export function ecdsaVerify(key, content, signature, alg, crv) {
  let publicKey;
  let digest_alg = getAlg(alg);
  let curve = getCurve(crv);

  try {
    publicKey = createPublicKey({
      key: key,
      format: "raw-public",
      asymmetricKeyType: "ec",
      namedCurve: curve,
    });
  } catch {
    throw "Invalid ECDSA public key";
  }

  try {
    return verify(digest_alg, content, {
      key: publicKey,
      dsaEncoding: "ieee-p1363",
    }, signature);
  } catch {
    throw "ECDSA verify error";
  }
}


export function eddsaSign(key, content, crv) {
  let privateKey;
  let curve = getCurve(crv);

  try {
    privateKey = createPrivateKey({
      key: key,
      format: "raw-private",
      asymmetricKeyType: curve,
    });
  } catch {
    throw "Invalid EDDSA private key";
  }

  try {
    return sign(null, content, privateKey);
  } catch {
    throw "EDDSA sign error";
  }
}

export function eddsaVerify(key, content, signature, crv) {
  let publicKey;
  let curve = getCurve(crv);

  try {
    publicKey = createPublicKey({
      key: key,
      format: "raw-public",
      asymmetricKeyType: curve,
    });
  } catch{
    throw "Invalid EDDSA public key";
  }

  try {
    return verify(null, content, publicKey, signature);
  } catch {
    throw "EDDSA verify error";
  }
}

export function rsaOaepEnc(key, cek, alg) {
  let publicKey;
  let digest_alg = getAlg(alg);

  try {
    publicKey = createPublicKey({
      key: key,
      format: "der",
      type: "pkcs1"
    });
  } catch  {
    throw "Invalid RSA OAEP key";
  }

  try {
    return publicEncrypt(
      {
        key: publicKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: digest_alg
      },
      cek
    );
  } catch {
    throw "RSA OAEP encryption error"
  }

}

export function rsaOaepDec(key, cek, alg) {
  let privateKey;
  let digest_alg = getAlg(alg);

  try {
    privateKey = createPrivateKey({
      key: key,
      format: "der",
      type: "pkcs1"
    });
  } catch {
    throw "Invalid RSA OAEP key";
  }

  try {
    return privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: digest_alg
      },
      cek
    );
  } catch {
    throw "RSA OAEP decryption error"
  }
}
export function rsaPssSign(key, content, alg) {
  let privateKey;
  let digest_alg = getAlg(alg);
  let saltLength = 64;
  if (alg === PS256){
    saltLength = 32;
  } else if (alg === PS384) {
    saltLength = 48;
  } 

  try {
    privateKey = createPrivateKey({
      key: key,
      format: "der",
      type: "pkcs1"
    });
  } catch {
    throw "Invalid RSA private key";
  }

  try {
    return sign(digest_alg, content, {
      key: privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: saltLength,
    });
  } catch {
    throw "RSA sign error";
  }
}

export function rsaPssVer(key, signature, content, alg) {
  let publicKey;
  let digest_alg = getAlg(alg);
  let saltLength = 64;
  if (alg === PS256){
    saltLength = 32;
  } else if (alg === PS384) {
    saltLength = 48;
  } 

  try {
    publicKey = createPublicKey({
      key: key,
      format: "der",
      type: "pkcs1"
    });
  } catch {
    throw "Invalid RSA public key";
  }

  try {
    return verify(
      digest_alg, 
      content, {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: saltLength
      }, 
      signature
    );
  } catch {
    throw "RSA verify error";
  }
}
