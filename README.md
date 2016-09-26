# a Python library for decrypting Apple Pay payment tokens.

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
import "applepay"

# payment_json value example:
#
#    {"data":"<<Base64EncodedData>>",
#     "header":
#         {"publicKeyHash":"<<Base64EncodedData>>",
#          "ephemeralPublicKey":"<<Base64EncodedData>>",
#          "transactionId":"<<HexifiedData>>"},
#     "version":"EC_v1"}

payment = applepay.Payment(payment_json)

certificate_pem = File.read("mycert.pem")
private_key_pem = File.read("private_key.pem")

decrypted_json = payment.decrypt(certificate_pem, private_key_pem)

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
$ python tests/applepay_test.py
...
5 tests, 18 assertions, 0 failures, 0 errors, 0 skips
```

## Contributors