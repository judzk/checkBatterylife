[CmdletBinding(SupportsShouldProcess = $true)]
Param(
	[Switch]$test = $False,
	[Switch]$vpn = $False,
	[ValidateSet("DEBUG","INFO","WARNING","ERROR")]
	[String]$loglevel = "INFO"
)
# Conf pour le log : https://github.com/EsOsO/Logging/wiki
Set-LoggingDefaultLevel -Level $loglevel
Add-LoggingTarget -Name File -Configuration @{Path = '.\Logs\battery_%{+%Y%m%d}.log'}
Add-LoggingTarget -Name Console -Configuration @{
	ColorMapping = @{
		DEBUG   = 'Gray'
		INFO    = 'Green'
		WARNING = 'Yellow'
		ERROR   = 'Red'
	}
}
Set-Location $PSScriptRoot
Import-Module "$PSScriptRoot\Modules\PSGLPI.psm1" # https://github.com/J-C-P/PSGLPI
Function Get-IniContent {
	<#
	.Synopsis
		Gets the content of an INI file
 
	.Description
		Gets the content of an INI file and returns it as a hashtable
 
	.Notes
		Author : Oliver Lipkau <oliver@lipkau.net>
		Source : https://github.com/lipkau/PsIni
					  http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
		Version : 1.0.0 - 2010/03/12 - OL - Initial release
					  1.0.1 - 2014/12/11 - OL - Typo (Thx SLDR)
											  Typo (Thx Dave Stiff)
					  1.0.2 - 2015/06/06 - OL - Improvment to switch (Thx Tallandtree)
					  1.0.3 - 2015/06/18 - OL - Migrate to semantic versioning (GitHub issue#4)
					  1.0.4 - 2015/06/18 - OL - Remove check for .ini extension (GitHub Issue#6)
					  1.1.0 - 2015/07/14 - CB - Improve round-tripping and be a bit more liberal (GitHub Pull #7)
										   OL - Small Improvments and cleanup
					  1.1.1 - 2015/07/14 - CB - changed .outputs section to be OrderedDictionary
					  1.1.2 - 2016/08/18 - SS - Add some more verbose outputs as the ini is parsed,
												  allow non-existent paths for new ini handling,
												  test for variable existence using local scope,
												  added additional debug output.
 
		#Requires -Version 2.0
 
	.Inputs
		System.String
 
	.Outputs
		System.Collections.Specialized.OrderedDictionary
 
	.Example
		$FileContent = Get-IniContent "C:\myinifile.ini"
		-----------
		Description
		Saves the content of the c:\myinifile.ini in a hashtable called $FileContent
 
	.Example
		$inifilepath | $FileContent = Get-IniContent
		-----------
		Description
		Gets the content of the ini file passed through the pipe into a hashtable called $FileContent
 
	.Example
		C:\PS>$FileContent = Get-IniContent "c:\settings.ini"
		C:\PS>$FileContent["Section"]["Key"]
		-----------
		Description
		Returns the key "Key" of the section "Section" from the C:\settings.ini file
 
	.Link
		Out-IniFile
	#>

	[CmdletBinding()]
	[OutputType(
		[System.Collections.Specialized.OrderedDictionary]
	)]
	Param(
		# Specifies the path to the input file.
		[ValidateNotNullOrEmpty()]
		[Parameter( Mandatory = $true, ValueFromPipeline = $true )]
		[String]
		$FilePath,

		# Specify what characters should be describe a comment.
		# Lines starting with the characters provided will be rendered as comments.
		# Default: ";"
		[Char[]]
		$CommentChar = @(";"),

		# Remove lines determined to be comments from the resulting dictionary.
		[Switch]
		$IgnoreComments
	)

	Begin {
		Write-Debug "PsBoundParameters:"
		$PSBoundParameters.GetEnumerator() | ForEach-Object { Write-Debug $_ }
		if ($PSBoundParameters['Debug']) {
			$DebugPreference = 'Continue'
		}
		Write-Debug "DebugPreference: $DebugPreference"
		Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"
		$commentRegex = "^\s*([$($CommentChar -join '')].*)$"
		$sectionRegex = "^\s*\[(.+)\]\s*$"
		$keyRegex     = "^\s*(.+?)\s*=\s*(['`"]?)(.*)\2\s*$"
		Write-Debug ("commentRegex is {0}." -f $commentRegex)
	}

	Process {
		Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath"

		$ini = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
		#$ini = @{}
		if (!(Test-Path $Filepath)) {
			Write-Verbose ("Warning: `"{0}`" was not found." -f $Filepath)
			Write-Output $ini
		}

		$commentCount = 0
		switch -regex -file $FilePath {
			$sectionRegex {
				# Section
				$section = $matches[1]
				Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding section : $section"
				$ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
				$CommentCount = 0
				continue
			}
			$commentRegex {
				# Comment
				if (!$IgnoreComments) {
					if (!(test-path "variable:local:section")) {
						$section = $script:NoSection
						$ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
					}
					$value = $matches[1]
					$CommentCount++
					Write-Debug ("Incremented CommentCount is now {0}." -f $CommentCount)
					$name = "Comment" + $CommentCount
					Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding $name with value: $value"
					$ini[$section][$name] = $value
				}
				else {
					Write-Debug ("Ignoring comment {0}." -f $matches[1])
				}

				continue
			}
			$keyRegex {
				# Key
				if (!(test-path "variable:local:section")) {
					$section = $script:NoSection
					$ini[$section] = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::OrdinalIgnoreCase)
				}
				$name, $value = $matches[1, 3]
				Write-Verbose "$($MyInvocation.MyCommand.Name):: Adding key $name with value: $value"
				if (-not $ini[$section][$name]) {
					$ini[$section][$name] = $value
				}
				else {
					if ($ini[$section][$name] -is [string]) {
						$ini[$section][$name] = [System.Collections.ArrayList]::new()
						$ini[$section][$name].Add($ini[$section][$name]) | Out-Null
						$ini[$section][$name].Add($value) | Out-Null
					}
					else {
						$ini[$section][$name].Add($value) | Out-Null
					}
				}
				continue
			}
		}
		Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FilePath"
		Write-Output $ini
	}

	End {
		Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
	}
}
Set-Alias gic Get-IniContent
$FileContent = Get-IniContent ".\config.ini"
# Connection à GLPI
if ($test){
	$AppURL = $FileContent["GLPI"].AppURL_test
} else {
	$AppURL = $FileContent["GLPI"].AppURL
}

$UserToken = $FileContent["GLPI"].UserToken
$ipv4 = (Get-NetIPConfiguration | Where-Object {$_.interfaceAlias -like "*stormshield*" -and $_.ipv4address -ne $null }).IPv4Address.IPAddress
if ( $ipv4 -like "10.3.0*" -or $vpn){
	$AppToken = $FileContent["GLPI"].AppToken_VPN
	Write-Log -Level 'DEBUG' -Message "VPN"
} else {
	$AppToken = $FileContent["GLPI"].AppToken
	Write-Log -Level 'DEBUG' -Message "Interne"
}

$credsGLPI = @{
	AppURL            = $Appurl
	UserToken         = $UserToken
	AppToken          = $AppToken
	AuthorizationType = "user_token"
}
$strGLPI = $credsGLPI | Out-String
Write-Log -Level 'DEBUG' -Message "credsGLPI : $strGLPI"
Set-GLPIToken -Creds $credsGLPI 2>$null
$SessionToken = GetGLPISessionToken -Creds $credsGLPI

# Déclaration des variables pour la connection à la base pgsql
$pgsql_user = $FileContent["wapt"].pgsql_user
$pgsql_pass = $FileContent["wapt"].pgsql_pass
$pgsql_host = $FileContent["wapt"].pgsql_host
$pgsql_port = $FileContent["wapt"].pgsql_port
$pgsql_db = $FileContent["wapt"].pgsql_db
Function Get-PSSQLDBConnexion{
	param(
		[Parameter(Mandatory=$true)] [String] $pgsql_host,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [String] $pgsql_port,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [String] $pgsql_db,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [String] $pgsql_user,
		[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [String] $pgsql_pass
	)
	Write-Log -Level 'DEBUG' -Message "sslmode=require;Driver={PostgreSQL Unicode(x64)};Server=$($pgsql_host);Port=$($pgsql_port);Database=$($pgsql_db);Uid=$($pgsql_user);Pwd=$($pgsql_pass);"
	$DBConnectionString = "Driver={PostgreSQL Unicode(x64)};Server=$($pgsql_host);Port=$($pgsql_port);Database=$($pgsql_db);Uid=$($pgsql_user);Pwd=$($pgsql_pass);sslmode=require;"
	$DBConn = New-Object System.Data.Odbc.OdbcConnection;
	Write-Log -Level 'DEBUG' -Message "connecting to DB."
	try {
		$DBConn.ConnectionString = $DBConnectionString ;
		$DBConn.Open();
		Write-Log -Level 'DEBUG' -Message "connected to DB."
	} catch {
		$ErrorMessage = $_.Exception.Message
		$ErrorType = $_.exception.GetType().fullname
		Write-Log -Level 'ERROR' -Message "Error in DB connection '$DBConnectionString' ; Error Details: $ErrorType - $ErrorMessage"
	}
	return $DBConn
}

function Get-SQLQuery{
	param(
	[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string] $SQLQuery,
	[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] [System.Data.Odbc.OdbcConnection] $Connexion
	)
	try {
		$cmd = New-object System.Data.Odbc.OdbcCommand($SQLQuery, $Connexion)
		$ds = New-Object system.Data.DataSet 
		(New-Object system.Data.odbc.odbcDataAdapter($cmd)).fill($ds) | Out-Null
	} catch {
		$ErrorMessage = $_.Exception.Message
		$ErrorType = $_.exception.GetType().fullname
		Write-Log -Level 'ERROR' -Message "Error while Querying DB '$Connexion' with '$SQLQuery' ; Error Details: $ErrorType - $ErrorMessage"
		exit
	}
	return $ds.Tables[0]
}
# Connexion à la bd PGSQL
$Connexion = Get-PSSQLDBConnexion $pgsql_host $pgsql_port $pgsql_db $pgsql_user $pgsql_pass

$today = Get-Date

# Requete pour récupérer toutes les machines aillant une information sur la batterie
$SQLQuerryString = "SELECT
hosts.computer_name as computer,
last_audit_on::timestamp as time,
(replace(replace(hostpackagesstatus.last_audit_output,'Auditing',''),'ecl-checkBatteryLife',''))::json->>'returnReason' as result
FROM
hostpackagesstatus
LEFT JOIN hosts on hosts.uuid = hostpackagesstatus.host_id
WHERE hostpackagesstatus.last_audit_output ILIKE '%%NOK%%' AND hostpackagesstatus.package = 'ecl-checkBatteryLife'
order by time"
$SQLDataSet = Get-SQLQuery -Connexion $Connexion -SQLQuery $SQLQuerryString
$SQLDataSet | ForEach-Object {If ([math]::Round($_.result) -lt 75){
		$createTicket = $False
		$infoFiche = $False
		Write-Log -Message $_.computer -Level debug
		$fiche = Search-GlpiItem -ItemType "Computer" -SearchOptions ("AND", 1, "is", "^$($_.computer)"), ("OR", 1, "is", "Prêt - PC portable $($_.computer)") -ForceDisplay @("1","2","31","6","25")
		$user = Get-GlpiSubItems -ItemType computer -id $fiche.2 -relation user
		$deliveryDate = (Get-GlpisubItems -ItemType computer -ID $fiche.2 -relation Infocom).delivery_date
		if ( $deliveryDate -eq $null){
			$createTicket = $True
			$nameTicket = "La machine $($_.computer) n'a pas de date de livraison sur sa fiche"
			$Details = @{
				name= $nameTicket
				content="Merci de remplir la date de livraison de ce poste ( récupérable depuis le site de Dell/HP)"
				itilcategories_id=29
				type=1
			}
			write-Log -Level info "La machine $($_.computer) n'a pas de date de livraison sur sa fiche"
			$infoFiche = $True
		} else {
			$endOfGaranty = (get-date $deliveryDate).AddYears(3)
			Write-Log -Message "Fin de la garantie : $(get-date $endOfGaranty -Format `"MM/dd/yyyy`")" -Level debug
			if ($today - $endOfGaranty -lt 3){
				$createTicket = $True
				write-Log -Level info "La batterie de $($_.computer) est à $($_.result)%, sa garantie finit le $(get-date $endOfGaranty -Format `"MM/dd/yyyy`") "
				$nameTicket = "Votre machine $($_.computer) a un soucis de batterie"
				$Details = @{
					name= $nameTicket
					content="Bonjour,
					la batterie du votre ordinateur ( $($_.computer) ) est à $($_.result)% de sa capacité d'origine, sa garantie finissant le $(get-date $endOfGaranty -Format `"MM/dd/yyyy`") nous allons contacter le support pour la remplacer.
					Cordialement, l'équipe maintenance du PRI"
					itilcategories_id=29
					type=1
				}
			}
		}
		if ( $createTicket){
			Write-Log -Level 'DEBUG' -Message "Nom ticket : $nameTicket"
			# On cherche si un ticket sur cette machine est encore ouvert
			$ticketGLPI= Search-GlpiItem -ItemType Ticket -SearchOptions (("AND", 12, "is", "2"),("AND", 1, "is", $nameTicket)) -ForceDisplay @("2","12")
			if ( $ticketGLPI -eq $null){
				Write-Log -Level 'DEBUG' -Message "Creation ticket"
				$createTicket = Add-GlpiItem -ItemType Ticket -Details $Details
				# Ajout de la machine dans élèment
				$Details = @{
					itemtype="Computer"
					items_id= $fiche.2
					tickets_id=$createTicket.id
				}
				Add-GlpiItem -itemtype Item_Ticket -Details $Details
				if (!$infoFiche){
					# Ajout de l'utilisateur en demandeur
					$fields=@{
						users_id= $user.id
						tickets_id=$createTicket.id
						type="1" # Requester  1; // Assign    2; // Observer  3;
						use_notification="1"
					}

					$Details = @{input=$fields}
					$json = $Details | ConvertTo-Json
					Invoke-RestMethod "$($Script:credsGLPI.AppURL)/Ticket/$($createTicket.id)/Ticket_User/" -Method Post -Headers @{"session-token"=$SessionToken.session_token; "App-Token" = "$($Script:credsGLPI.AppToken)"} -Body  ([System.Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json; charset=utf8'
				}
			} else {
				Write-Log -Level 'DEBUG' -Message "Ticket trouvé : $($ticketGLPI.2)"
			}
		}
	}
}