class Node {
    [string]$Hostname
    [string]$IPAddress
    [string]$OperatingSystem
    [int]$TTL
    [System.Management.Automation.Runspaces.PSSession]$Session
  
    Node() {
      $this.Hostname = ""
      $this.IPAddress = ""
      $this.OperatingSystem = ""
      $this.TTL = 0
    }
}