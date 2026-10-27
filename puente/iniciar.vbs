' Heimdall · arranca el puente sin ventana y lo reinicia si se cierra
Set sh = CreateObject("WScript.Shell")
dir = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
Do
  sh.Run "node """ & dir & "\puente.mjs""", 0, True
  WScript.Sleep 15000
Loop
