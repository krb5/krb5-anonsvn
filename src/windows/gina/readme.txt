GINA -- Graphical Identification and Authentication DLL.

To install the gina DLL, copy it into %systemroot%\system32, add 
a registry value of type REG_SZ named GinaDLL under the key
\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon,
and reboot the machine.

WARNING! - This sample is intended only as a demonstration of Gina 
related APIs, and should not be considered production quality code.
It is possible to make your machine unusable if you install a replacement
Gina and it breaks.  To avoid this situation, be sure that you have a
method of accessing the %systemroot%\system32 directory independent of
the Windows NT installation you are testing on.  

If the Gina sample malfunctions, and you are not able to logon to fix 
the problem, you can recover by doing one of the following:

* IF the test machine is on the network, and you have an account on 
another machine with Administrative privileges on the test machine,
THEN open the test machine registry remotely with regedt32 and delete
the GinaDLL value.

* IF the test machine is on the network, and %systemroot%\system32 is 
available on a network share for that machine (e.g. \\name\c$), THEN 
rename gina.dll to something else (e.g. 
ren \\name\c$\winnt351\system32\gina.dll gina.sdk), reboot the test
machine, and delete the GinaDLL value from the registry.

* IF the test machine will dual boot to another version of Windows NT
or another operating system capable of accessing %systemroot%\system32,
THEN boot to that operating system, delete %systemroot%\system32\gina.dll,
reboot, and delete the GinaDLL value from the registry.


For more information see: gina.hlp.
