
https://github.com/speedrun-program/amnesia_load_screen_tool

# INSTRUCTIONS

---------------------------------------------------------------------------------------------------
how to make the game skip flashbacks in load screens:
---------------------------------------------------------------------------------------------------
- **CHECK IF THE MODERATORS ALLOW THIS.**
  
  when this was written, the mods said they wouldn't let people use this feature.
  
  check if they allow this. If they don't, but you want to use it, tell them you think they should allow it.

- in amnesia_settings.txt, set "skip flashbacks" to "y".


---------------------------------------------------------------------------------------------------
how to make the game wait through flashbacks in load screens:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "skip flashbacks" to "n".


---------------------------------------------------------------------------------------------------
how to have menuing load delays for the main menu and for maps in quitouts which you quitout in:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "delay files" to "y".


---------------------------------------------------------------------------------------------------
how to turn off the menuing load delays for the main menu and for maps in quitouts which you quitout in:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "delay files" to "n".


---------------------------------------------------------------------------------------------------
how to adjust load delays or add or remove maps in maps_and_delays.txt:
---------------------------------------------------------------------------------------------------
- at the start of the line, write the map name followed by a forward slash. leading or trailing whitespace will be included.

- after the forward slash, put the delay in milliseconds.

- if there's no text before the forward slash, the delay is used for the main menu

- example 1: "12_storage/ 1575"
  
  this will give the loads from main menu for the Storage map a delay of 1575 milliseconds.
  
  example 2: "/ 1000"
  
  this will give loads for the main menu when exiting the game a delay of 1000 milliseconds.


---------------------------------------------------------------------------------------------------
how to add more flashbacks:
---------------------------------------------------------------------------------------------------
- add the sound files to flashback_names.txt.

- the sound files used by each flashback in are listed in the .flash files in \Amnesia The Dark Descent\flashbacks.

- in English, the sound files are in \Amnesia The Dark Descent\lang\eng\voices\flashbacks.
  
  in Russian, the sound files are in \Amnesia The Dark Descent\lang\rus\voices\flashbacks.
  
  you can listen to them to check if they're the ones you want to skip.


---------------------------------------------------------------------------------------------------
how to use the tool with versions of the game it wasn't specifically made for:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "allow unexpected game versions" to "y".


---------------------------------------------------------------------------------------------------
how to skip checking for updates when injecting Amnesia with the tool:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "check for tool updates" to "y".


---------------------------------------------------------------------------------------------------
how to use the tool when it isn't, or might not be, the most recent version:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, set "allow not fully updated tool" to "y".


---------------------------------------------------------------------------------------------------
how to adjust the amount of time that can remain in a flashback dialogue line before the next map loads:
---------------------------------------------------------------------------------------------------
- in amnesia_settings.txt, adjust the "milliseconds remaining before unwait" setting.
