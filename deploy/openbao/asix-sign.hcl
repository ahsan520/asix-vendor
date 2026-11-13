# The ONLY rights the vendor server has in OpenBao: ask the license key to sign something, and read its public half.
# It cannot read, export, back up, rotate, delete or configure the key, and it cannot touch anything else.
path "transit/sign/asix-license" {
  capabilities = ["update"]
}
path "transit/keys/asix-license" {
  capabilities = ["read"]
}
