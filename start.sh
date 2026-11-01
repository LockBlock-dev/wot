#!/usr/bin/env bash
clear && go run ./cmd/wotproxy \
  -upstream login.p2.worldoftanks.eu:20016 \
  -dump ../captures/proxy-$(date +%Y%m%d-%H%M).hex \
  -mitm-privkey ../mitm/loginapp_mitm.privkey \
  -mitm-pubkey ../World_of_Tanks_EU/2.4.0.0/res/loginapp_wot.pubkey \
  -baseapp-listen 127.0.0.1:32901 \
  -quiet \
  -battle-feed \
  -battle-own ExampleUser \
  -battle-side enemy \
  -battle-watch '' \
  -battle-margin 25
