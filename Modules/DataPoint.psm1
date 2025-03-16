enum TechniqueCategory {
    Uncategorized
    Persistence
    LateralMovement
    ImpairDefenses
}
class DataPoint {
    [string]$jobname
    [scriptblock]$scriptblock
    [bool]$isEnabled
    [string]$mitreID
    [TechniqueCategory]$techniqueCategory

    DataPoint($jobname, $scriptblock, $isEnabled, $mitreID, $techniqueCategory){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = $mitreID
        $this.techniqueCategory = $techniqueCategory
    }

    DataPoint($jobname, $scriptblock, $isEnabled){
        $this.jobname = $jobname
        $this.scriptblock = $scriptblock
        $this.isEnabled = $isEnabled
        $this.mitreID = "N/A"
    }

    enable(){
        $this.isEnabled = $true
    }

    disable(){
        $this.isEnabled = $false
    }
 }