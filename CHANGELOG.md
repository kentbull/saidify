# SAIDify Changelog

## 1.0.0

- Merge `urn:said` PR from [setayesh78](https://github.com/setayesh78), Carly Huitema's team at the University of Guelph.
- Delete the unnecessary KERI and ACDC genus and protocol version support - see keri-ts or keripy if that is needed.

## 0.1.0

Completed first functional version of the library.

- Provides `saidify`, a single function as the API to the library.
- Generates a valid, qualified, Base64URLSafe encoded (qb64) SAID from a JSON object and a label.

Warning: The equivalent Saider.verify() function may not yet be working.
