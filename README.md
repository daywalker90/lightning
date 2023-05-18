# Hodlvoice
A patched cln-grpc to allow holding of invoices.

### Build
Have an up-to-date [rustup](https://rustup.rs/) installed. Then:
* ``git clone https://github.com/daywalker90/lightning.git``
* ``cd lightning``
* ``git checkout hodlvoice`` (this should not be necessary but just in case)
* ``cargo build --release``

The ``cln-grpc-hodl`` binary will be ``target/release/cln-grpc-hodl``

### Installation
Put this in your cln config file (usually ``~./lightning/config``):

```
important-plugin=/path/to/cln-grpc-hodl
grpc-hodl-port=portnum
```

### Documentation
New grpc methods are:
* HodlInvoice (Create an invoice that will be held until close to invoie expiry or if an htlc is close to expiry.)
* HodlInvoiceSettle (Settles the htlcs being held.)
* HodlInvoiceCancel (Rejects the htlcs that may be held right now.)
* HodlInvoiceLookup (Lookup the state of an invoice created with HodlInvoice. State can be: OPEN, SETTLED, CANCELED, ACCEPTED)
* DecodeBolt11 (An extra decode method that also supports route hints.)

Check ``cln-grpc/proto/node.proto`` for their request and response fields.

### Example to generate python code from proto files
This needs the python packages grpcio and grpcio-tools

* ``cd cln-grpc/proto``
* ``python3 -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. node.proto primitives.proto``
