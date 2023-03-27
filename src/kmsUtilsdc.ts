
import { DecryptCommandInput, KMS } from "@aws-sdk/client-kms";
import util from 'util'
import { Buffer } from 'buffer'

export const kmsConfig = {
  accesKeyId: '',
  secretAccessKey: '',
  region: '', // example : us-east-1
  keyId: '',
  arn: '', // KMS
}

export const region = kmsConfig.region;

export const kms = new KMS({
  region: region,
  apiVersion: "2014-11-01",
  credentials: {
    accessKeyId: kmsConfig.accesKeyId,
    secretAccessKey: kmsConfig.secretAccessKey,
  },
  // for react-native
  // endpoint: {
  //   hostname: "kms." + region + ".amazonaws.com",
  //   path: "",
  //   protocol: "https",
  // }
});

export async function kmsEncryption(data) {
  // a client can be shared by different commands.

  try {
    let encryptionParams = {
      KeyId: kmsConfig.arn,
      Plaintext: Buffer.from(data, "base64"),
    };

    let kmsEncrypt = util.promisify(kms.encrypt).bind(kms);

    let encryptedData = await kmsEncrypt(encryptionParams);

    //encryptedData contained 2 parts, CiphertextBlob and KeyId
    console.log("Encrypted", encryptionParams);
    return encryptedData;

  } catch (error) {
    console.log("\nerror => \n", error);
  }
}


export const kmsDecryption = async (encryptedData: any) => {
  try {
    let buff = Buffer.from(encryptedData.CiphertextBlob);
    let encryptedBase64data = buff.toString("base64");
    console.log("\nencryptedBase64data => \n", encryptedBase64data);

    let decryptionParams: DecryptCommandInput = {
      CiphertextBlob: encryptedData.CiphertextBlob,
    };

    let kmsDecrypt = util.promisify(kms.decrypt).bind(kms);
    let decryptedData = await kmsDecrypt(decryptionParams);

    // decryptedData contained 2 parts, Plaintext and KeyId
    console.log("\ndecryptedData => \n", decryptedData);
    console.log("\ndecryptedData.Plaintext => \n", decryptedData.Plaintext);
    console.log("\ndecryptedData.KeyId => \n", decryptedData.KeyId);

    let buff2 = Buffer.from(decryptedData.Plaintext, "base64");
    let originalText = buff2.toString();
    console.log("\noriginalText => \n", originalText, Buffer.from(decryptedData.Plaintext).toString());
    return originalText;
  } catch (error) {
    console.log("\ndecrypt error => \n", error);
  }
}

export async function encrypt(source) {
  // if source.length%3 == 1 then it works 
  source += "a"
  const params = {
    KeyId: kmsConfig.arn,
    Plaintext: Buffer.from(source, "base64"),
  };
  const { CiphertextBlob } = await kms.encrypt(params);
  console.log("ENCRYPTED")
  // store encrypted data as base64 encoded string
  return Buffer.from(CiphertextBlob).toString("base64");
}

// source is plaintext
export async function decrypt(source) {
  const params = {
    CiphertextBlob: Buffer.from(source, 'base64'),
  };
  const data = await kms.decrypt(params);
  let original = Buffer.from(data.Plaintext).toString("base64")
  if (original.includes("="))
    original = original.split("=")[0].slice(0, -1);
  console.log("DECRYPTED")
  return original;

}
