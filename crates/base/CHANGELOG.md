# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

## [3.0.0] - 2026-08-26

Initial version, exposes the traits, serialization, key and secret that where
previously defined by `core`.

- implement `Serializable` for `BTreeSet` and `BTreeMap`

*Note*: version is not v1.0.0 since there was a pre-existing version of
`cosmian_crypto_base` at version v2.0.0. In order to re-use the name, directly
bump to v3.0.0.
