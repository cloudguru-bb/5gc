Samsung Galaxy S23 dial pad codes for network mode settings. Here are the key codes you're looking for:
Main Network Mode Menu:

*#*#4636#*#* - Opens Phone Information/Testing menu where you can change network types


Direct LTE/Data Mode Codes:

*#*#2263#*#* - Band selection and network mode menu
*#0011# - Service mode (shows current network info and some settings)

In the Phone Information menu (##4636##):

Tap on "Phone Information" or "Phone Information 1"
Look for "Set Preferred Network Type" dropdown
Select "LTE only" or "LTE/GSM/WCDMA" depending on your needs

Alternative method:

Go to Settings > Connections > Mobile Networks > Network Mode
Select "LTE/3G/2G (auto connect)" or "LTE only"

Note: Some of these codes may vary slightly depending on your specific S23 model (S23, S23+, S23 Ultra) and carrier firmware. The *#*#4636#*#* code is the most universally reliable for accessing network mode settings.
Be cautious when changing these settings, as selecting "LTE only" might cause issues if LTE coverage is poor in your area, potentially leaving you without any cellular connection.

-  -  -  -  -  -  -  -  -  -  -  -  -  -  -  
Field testing notes:
- *#*#4636#*#* - Opens Phone Information/Testing menu with "LTE only" seems to help avoid the dual attach issue.  The device is sticking to the selected carrier better.
- The dual attach error is often identifiable by being attached for a few minutes then unexpectedely having service terminated.
- CellularZ and G-NetTrack Pro were useful in discovering data.


For the Google Pixel 8 Pro, here are the dial codes to force LTE-only mode and avoid dual attach issues:
Primary Method:

*#*#4636#*#* - Opens Phone Information/Testing menu

Tap "Phone Information"
Find "Set Preferred Network Type" dropdown
Select "LTE only" (this prevents fallback to 3G/2G)



Alternative Codes:

*#*#INFO#*#* - Alternative way to access phone info menu
*#0*# - General service menu (may have network options depending on firmware)

In the Phone Information Menu:
Look for these specific network type options:

"LTE only" - Forces device to only use LTE networks
"NR only" - 5G only (if you want to avoid LTE entirely)
"LTE/NR only" - LTE and 5G only, no 3G/2G fallback

Additional Settings Path:
Settings > Network & Internet > SIMs > Preferred network type > Select "LTE" or "5G"
Important Notes for Pixel 8 Pro:

The Pixel 8 Pro supports 5G, so you might also see "NR only" or "5G only" options
"LTE only" mode will prevent the dual attach scenarios you're trying to avoid
Some carrier-locked devices may have limited access to these menus

The *#*#4636#*#* code is your best bet for reliable access to these network mode settings on Pixel devices. This will definitively prevent any 3G attachment attempts that could interfere with proper LTE registration.
