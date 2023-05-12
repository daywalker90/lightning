# Hodlvoice
A patched cln-grpc to allow holding of invoices.

### Build
Have an up-to-date [rustup](https://rustup.rs/) installed.
``git clone https://github.com/daywalker90/lightning.git``
``cd lightning``
``cargo build --release``

The ``cln-grpc-hodl`` binary will be ``target/release/cln-grpc-hodl``

### Installation
Put this in your cln config file (usually ``~./lightning/config``):
``important-plugin=/path/to/cln-grpc-hodl``
``grpc-hodl-port=portnum``

### Documentation
New grpc methods are:
* HodlInvoice
* * Create an invoice that will be held until close to invoie expiry or if an htlc is close to expiry.
* HodlInvoiceSettle
* * Mark an invoice as settled so the plugin settles the htlcs being held.
* HodlInvoiceCancel
* * Mark an invoice as cancelled so the plugin rejects the htlcs that may be held right now.
* HodlInvoiceLookup
* * Lookup the state of an invoice created with HodlInvoice. State can be: OPEN, SETTLED, CANCELED, ACCEPTED
* DecodeBolt11
* * An extra decode method that also supports route hints

Check ``cln-grpc/proto/node.proto`` for their request and response fields.

### Example to generate python code from proto files
This needs the python packages grpcio==1.43.0 and grpcio-tools==1.43.0
``cd cln-grpc/proto``
``python3 -m grpc_tools.protoc --proto_path=. --python_out=. --grpc_python_out=. node.proto primitives.proto``
