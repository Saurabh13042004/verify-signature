const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const inputPayload = {
    ResponseSignatureEncryptedValue: 'PDOMVBSaUCV31DNJmoAvp22BRDqzyOJmrHznMekcbnvzGpaAYSJjMBntYHVyEbdLkFYATWH4XVZnnxDJfH0YCDGecH0JePL2Hp3XTqddKXdkJJ7IOZAyI1PoBa+T5KWtdxQ0+UIRhvvIrum5KXJl43+YMSEJGiaTYE1/6aGx5B5ywEOqn+3PSudm3dZQ22fTJ3Xye6D2B30OIM7kZhe6Wtfukxv1q76SWVsPy51yHjTOeloJuvBZsToNV6SH9SgsLEwqff0u27U+rsg7h8hnxt8wZ1/8Bv609bJdgLITepd8GWYTmresg6yefvf8sqCGqiLXCYQTeBLAniAoCtiGcAzLu9YRpLHcfzZ8kYySkBW6Q7A68sXrNG/jgRhh1BySI3ipBoVxWuc++pK75Vd1VKwKwma26BpplvOi2QHlybMTm7rpp0rjhRHUJtHmnghePrI38d8T87qWJNrwnUv6ys4TL9Z5jyyKdycIwMachHhWq6sS1lVFQKE8loV8KSKNddCyMkcRGHwdXZ/s/E/HmBbX0bAAIkc+E3JJyb+mrhyU4bvO4wLlv8fGv+/4PuQL38i/+DXak0r6Bq91LnrO0GIXJXo70or05+GNHJGCohwTb42u32fuYxGihNLKh4nW+6F7GZwohOptQEd14Z9Ew7CjHnd2D+AAIuoOxYE8hrnBRP5sNynVLckOtrlSd/Ew6E3S5WXD6X1E3aTAtNJrqEAbq2P+YRvWeP3Vzel3Ij7xIY+QHfV6Skg0XWu1pad4',
    GWSymmetricKeyEncryptedValue: 'A2Z0G6ySFcqMYr1EUn3SZqqUPTJUrIREEpVWlSTABl3zSgvZViUwzjWWWoGNdOAVRo4yOcJWBGFXTJiDSFmxDVx7fKbrDtgCf99C2J7XH3jrTEY8hj8V94xxSbpnlwDXAiztbYflkJSpwKUlQ/Yc0nHkPgQxmoh6r3oI536rlPpbRAVOImxKV1se6NJfn7tM/APlzKHo6dVd4RGrgegQi5KcqyQME5VY+OIHgtatLVH2jvyFrsRdvCsDCHQOx3FhoNaZsK3jbOVa3+A7WNhqh+QLoQ1N35u9oZFERDVlsTLzLnU0VYKiQY4g0ExwSOfYwjl0l/Ger8CB0vV1M6V9rn7/rV/jUZZVZRYhA5LIaJQVY6e2kerLN/u7m/pCQPpk8IF85+rpTVTbrcDZ0DtW0eyFHtCJ6mKb48UPdyh2ePRzcJ/sQFjuNNdlZIyKpHmB+4uikwHY7XUyjqynnDKJdiPpoLxy5nUGwdfRMqUJ5xuxwJwtDF1Zmtmgh1JhUIwAS6PiFO+CdIqzxVTt9wfRN1VNz9tMgS6148B3i2G96xu1Uu7DYBftAknJ//DKupMBFnRBVnmFVoLJ3gOPbOR6QXAxYMRGfWIGMFhxZvpNw641VbSqbRkQkftVijw9Bu/NUTQWPowOwi7NBVTf3pNVRnzyDbfGCDSiPauqDBqvua0=',
    Scope: 'CBXMGRT3',
    TransactionId: 'Swc6CXQ1ayJjoTRT',
    Status: 'SUCCESS'
};

const symmetricKey = Buffer.from('7509885242774820B1ddOAOhsJzOZnvq', 'utf8');
const iv = Buffer.from('00000000000000000000000000000000', 'hex');

const encryptedSignatureBuffer = Buffer.from(inputPayload.ResponseSignatureEncryptedValue, 'base64');

const algorithm = 'aes-256-cbc';
const decipher = crypto.createDecipheriv(algorithm, symmetricKey, iv);

let decrypted;
try {
    decrypted = Buffer.concat([decipher.update(encryptedSignatureBuffer), decipher.final()]);

    const ivLength = 16;
    const ivBuffer = decrypted.slice(0, ivLength);
    const digitalSignature = decrypted.slice(ivLength);

    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUlK8MdCzJb5ROqmfW6B
/KnXsAhWaHM8JNV3XmY0yyzZw4QsQKaqGoAvujKSwQeS1Uq+uJGcRXvmoWrMlqWA
cLeGxswGCCVptS/gu2JP/hQ+r3bo7Xv9Jb4KdVQN7IGJUt9BZ4lb9tWRjgseSTNx
sicFUpVj68Xw+ZWYZXdhARm3TtkhYmNKuMstVe9rA7dTQdAj9D/MJFZ7r+axC9n0
uj6M6I2QdS5EoV+Bvoerb669duen6dvgFBRJSp93dO0WpotJT+z9oeCbJEUIxgK/
Td/mjUWgD0+DbR8KIkZ9OLCB2rFXH0UzkLCEpooWeGW7ZA8nmsU7/eQrPBcx3EdU
xwIDAQAB
-----END PUBLIC KEY-----`;

    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(digitalSignature);
    verify.end();

    const isVerified = verify.verify(publicKey, digitalSignature, 'base64');

    if (!isVerified) {
        const base64Url = digitalSignature.toString('base64');
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const token = Buffer.from(base64, 'base64').toString();
        console.log('Original JWT Token:', token);

        jwt.verify(token, publicKey, (err, decoded) => {
            if (err) {
                console.error('Error verifying token:', err);
            } else {
                console.log('Decoded payload:', decoded);
            }
        });
    } else {
        console.error('Signature verification failed.');
    }

} catch (error) {
    console.error('Error:', error);
}
