# Converted from Sigma rule: Suspicious PowerShell Execution
# Original Sigma ID: 8f5a6b7c-8d9e-4f0a-1b2c-3d4e5f6a7b8c
# Description: Detects suspicious PowerShell command line arguments
# Author: Your Name
# MITRE ATT&CK: attack.execution, attack.t1059.001

event Sigma_Suspicious_PowerShell_Execution:
key:
filter {(Image|endswith == "\powershell.exe" && (CommandLine|contains == "-enc" || CommandLine|contains == "-EncodedCommand" || CommandLine|contains == "IEX" || CommandLine|contains == "Invoke-Expression"))}

rule Sigma_Suspicious_PowerShell_Execution: Sigma_Suspicious_PowerShell_Execution

emit {
    $correlation_type = "event"
    $importance = "high"
    $object = "process"
    $action = "execute"
    $status = "success"
    $subject = "account"
    $datafield1 = "Suspicious PowerShell Execution"
    $datafield2 = "Detects suspicious PowerShell command line arguments"
    $datafield3 = "8f5a6b7c-8d9e-4f0a-1b2c-3d4e5f6a7b8c"
    $datafield4 = "https://attack.mitre.org/techniques/T1059/001/"
    $datafield5 = "attack.execution", "attack.t1059.001"
    $datafield6 = "t1059.001"
}
