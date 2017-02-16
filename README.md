# A Python library for decrypting Apple Pay payment tokens.

ApplePay reference https://developer.apple.com/library/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

## Apple's intermediate and root certificates

```sh
$ wget 'https://www.apple.com/certificateauthority/AppleAAICAG3.cer'
$ wget 'https://www.apple.com/certificateauthority/AppleRootCA-G3.cer'
```

## Install

Installing library into your environment:

```sh
$ pip install applepay
```

## Usage

Step by step:


```python
from applepay import payment as apple

# payment_json value example:
#
#    {"data":"<<Base64EncodedData>>",
#     "header":
#         {"publicKeyHash":"<<Base64EncodedData>>",
#          "ephemeralPublicKey":"<<Base64EncodedData>>",
#          "transactionId":"<<HexifiedData>>"},
#     "version":"EC_v1"}


certificate_pem = open('merchant_cert.pem', 'rb').read()
private_key_pem = open('merchant_private_key', 'rb').read()

payment = apple.Payment(certificate_pem, private_key_pem)

decrypted_json = payment.decrypt(payment_json['header']['ephemeralPublicKey'], payment_json['data'])


# decrypted_json value example
#    {
#      "applicationPrimaryAccountNumber"=>"4804123456789012",
#      "applicationExpirationDate"=>"190123",
#      "currencyCode"=>"123",
#      "transactionAmount"=>700,
#      "deviceManufacturerIdentifier"=>"123456789012",
#      "paymentDataType"=>"3DSecure",
#      "paymentData"=> {
#        "onlinePaymentCryptogram"=>"<<Base64EncodedData>>",
#        "eciIndicator"=>"5"
#      }
#    }
```

## Testing

```sh
$ python setup.py test
```

## Contributors
