ApplePay reference https://developer.apple.com/library/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

## Install

Add to your `Gemfile`:

```python
pip install applepay"
```

## Usage

Step by step:


```python
import "applepay"

# payment_json (JSON encoded token):
#
#    {"data":"<<Base64EncodedData>>",
#     "header":
#         {"publicKeyHash":"<<Base64EncodedData>>",
#          "ephemeralPublicKey":"<<Base64EncodedData>>",
#          "transactionId":"<<HexifiedNumber>>"},
#     "version":"EC_v1"}

payment = applepay.Payment(payment_json)

certificate_pem = File.read("mycert.pem")
private_key_pem = File.read("private_key.pem")

decrypted_json = token.decrypt(certificate_pem, private_key_pem)

# decrypted_json value example
{
  "applicationPrimaryAccountNumber"=>"4804123456789012",
  "applicationExpirationDate"=>"190123",
  "currencyCode"=>"123",
  "transactionAmount"=>700,
  "deviceManufacturerIdentifier"=>"123456789012",
  "paymentDataType"=>"3DSecure",
  "paymentData"=> {
    "onlinePaymentCryptogram"=>"<<Base64EncodedData>>",
    "eciIndicator"=>"5"
  }
}
```

## Testing

```sh
$ python test/applepay_test.py
...
5 tests, 18 assertions, 0 failures, 0 errors, 0 skips
```

## Contributors