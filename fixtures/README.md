# Fixtures

`spl_record.so` is the SPL Record program as deployed on mainnet-beta at
`recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5` (last deployed in slot 356854496), fetched with:

```sh
solana program dump -um recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5 fixtures/spl_record.so
```

sha256: `dbc470deb72b63724a7faf7d27c3b82ac6f6f69b6d423fa1e8c503ea34beff15`

LiteSVM ships Token-2022, the ATA program and the ZK ElGamal Proof program, but not the record
program. The confidential transfer needs it: the U256 range proof of a fee-bearing transfer is
1064 bytes, too large for any transaction, so it is written into a record account and verified
from there.
