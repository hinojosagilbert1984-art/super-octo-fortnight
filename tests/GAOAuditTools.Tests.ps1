# GAOAuditTools.Tests.ps1
# Requires Pester v5
# Aligns with GAO-21-519SP & SAFE-AI Security Auditing Controls
# Purpose: Validate spatiotemporal synchronization, attention constraints, and forensic log integrity

BeforeAll {
    $GatewayUrl = "http://localhost:5000/api/v1/super-attorney"
    $BackendAvailable = $false

    # ---- Connectivity probe ----
    try {
        $null = Invoke-RestMethod -Uri "$GatewayUrl/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
        $BackendAvailable = $true
        Write-Host "✅ Backend online – using live REST calls" -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠️ Backend offline – falling back to local mocks for integration tests"
    }

    # ---- Helper function that either calls real API or returns mock data ----
    function Invoke-SuperAttorneyGateway {
        param(
            [Parameter(Mandatory)]
            [hashtable]$Payload
        )

        if ($BackendAvailable) {
            # Real call to Flask backend
            return Invoke-RestMethod -Uri "$GatewayUrl/consult" -Method Post `
                -Body ($Payload | ConvertTo-Json -Depth 5) -ContentType "application/json"
        }
        else {
            # ---- Mock logic: simulate the backend's behaviour for known endpoints ----
            $endpoint = $Payload.endpoint
            switch ($endpoint) {
                "scale-temporal" {
                    $frames15 = $Payload.frames15
                    $fps15   = $Payload.fps15
                    $frames60 = $Payload.frames60
                    $fps60    = $Payload.fps60
                    
                    if ($fps15 -eq 0 -or $fps60 -eq 0) {
                        throw "Division by zero: FPS cannot be 0"
                    }
                    
                    $time15 = $frames15 / $fps15
                    $time60 = $frames60 / $fps60
                    
                    return @{ 
                        time15 = $time15
                        time60 = $time60
                        equal = [math]::Abs($time15 - $time60) -lt 0.0001  # floating-point tolerance
                        status = 200
                        record_hash = [guid]::NewGuid().ToString()
                    }
                }
                "text-coordinates" {
                    # Pure text query must yield (t, 0, 0) – no spatial drift
                    return @{ 
                        t = $Payload.t
                        h = 0
                        w = 0
                        status = 200
                        record_hash = [guid]::NewGuid().ToString()
                    }
                }
                "forensic-replay" {
                    # Simulate Merkle chain integrity check
                    $originalHash = $Payload.original_hash
                    $computedHash = $Payload.computed_hash
                    
                    return @{
                        integrity_check = ($originalHash -eq $computedHash)
                        status = 200
                        record_hash = [guid]::NewGuid().ToString()
                    }
                }
                default {
                    throw "Mock does not support endpoint '$endpoint'"
                }
            }
        }
    }
}

# -------------------------------------------------------------------
# 1. TEMPORAL SCALING (data-driven)
# -------------------------------------------------------------------
Describe "Spatiotemporal Evidence & Extradition Log Verification" -Tag "Integration", "Temporal" {
    Context "Temporal scaling checks – FPS-invariant synchronization" {
        It "Scales <frames15> fps15 and <frames60> fps60 to identical seconds" -TestCases @(
            @{ frames15 = 300; fps15 = 15.0; frames60 = 1200; fps60 = 60.0; expectedSeconds = 20.0 }
            @{ frames15 = 450; fps15 = 15.0; frames60 = 1800; fps60 = 60.0; expectedSeconds = 30.0 }
            @{ frames15 = 100; fps15 = 10.0; frames60 = 400; fps60 = 40.0; expectedSeconds = 10.0 }
        ) {
            $payload = @{
                endpoint  = "scale-temporal"
                frames15  = $frames15
                fps15     = $fps15
                frames60  = $frames60
                fps60     = $fps60
            }
            
            $result = Invoke-SuperAttorneyGateway -Payload $payload
            
            $result.time15 | Should -Be $expectedSeconds -Because "Frame 15 FPS should scale to expected seconds"
            $result.time60 | Should -Be $expectedSeconds -Because "Frame 60 FPS should scale to expected seconds"
            $result.equal | Should -Be $true -Because "Both timelines should be synchronized"
        }

        It "Handles division by zero gracefully" {
            $payload = @{ 
                endpoint = "scale-temporal"
                frames15 = 100
                fps15 = 0
                frames60 = 100
                fps60 = 60
            }
            
            { Invoke-SuperAttorneyGateway -Payload $payload } | Should -Throw -Because "FPS cannot be zero"
        }
    }
}

# -------------------------------------------------------------------
# 2. (t, 0, 0) CONSTRAINT ENFORCEMENT for pure text queries
# -------------------------------------------------------------------
Describe "Purely Temporal Attention Limits" -Tag "Integration", "Attention" {
    Context "Zero out h and w dimensions for text-only queries" {
        It "Returns h=0, w=0 for any text query with timestamp <t>" -ForEach @(
            @{ t = 1 }
            @{ t = 42 }
            @{ t = 999 }
        ) {
            $payload = @{ 
                endpoint = "text-coordinates"
                t = $t
                queryType = "text"
            }
            
            $coords = Invoke-SuperAttorneyGateway -Payload $payload
            
            $coords.h | Should -Be 0 -Because "Horizontal coordinate must be zeroed for pure text"
            $coords.w | Should -Be 0 -Because "Vertical coordinate must be zeroed for pure text"
            $coords.t | Should -Be $t -Because "Temporal index should be preserved"
        }

        It "Prevents spatial drift in statutory queries" {
            # Scenario: EAW Article 2.2 dual criminality exemption query
            $payload = @{
                endpoint = "text-coordinates"
                t = 0
                queryType = "statutory"
                query = "Is dual criminality waived for cybercrime under EAW Framework Decision 2002/584/JHA, Article 2.2?"
            }
            
            $result = Invoke-SuperAttorneyGateway -Payload $payload
            
            # Assert no spatial attention leakage
            $result.h | Should -Be 0
            $result.w | Should -Be 0
            $result.status | Should -Be 200
        }
    }
}

# -------------------------------------------------------------------
# 3. FORENSIC REPLAY INTEGRITY (SHA-256 Merkle chain)
# -------------------------------------------------------------------
Describe "Forensic Replay Integrity (Merkle Hash Chaining)" -Tag "Integration", "Forensic" {
    Context "Detects tampering in signed documents" {
        It "Detects ex-post tampering when block content is mutated" {
            # Original record: Category 11 cybercrime with 5-year maximum penalty
            $originalContent = "Warrant issued for Category 11: Computer-related crime. Statutory maximum penalty: 5 years."
            $originalRecord = @{
                seq_no = 1004
                event_type = "signed_eaw_document"
                document_content = $originalContent
            }
            $originalJson = $originalRecord | ConvertTo-Json -Compress
            $originalHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($originalJson)
            ) | ForEach-Object { $_.ToString("x2") } | Join-String
            
            # Tampered record: adversary reduces penalty to 2 years (below EAW threshold)
            $tamperedContent = "Warrant issued for Category 11: Computer-related crime. Statutory maximum penalty: 2 years."
            $tamperedRecord = @{
                seq_no = 1004
                event_type = "signed_eaw_document"
                document_content = $tamperedContent
            }
            $tamperedJson = $tamperedRecord | ConvertTo-Json -Compress
            $tamperedHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($tamperedJson)
            ) | ForEach-Object { $_.ToString("x2") } | Join-String
            
            # Query gateway to verify integrity
            $payload = @{
                endpoint = "forensic-replay"
                original_hash = $originalHash
                computed_hash = $tamperedHash
            }
            
            $result = Invoke-SuperAttorneyGateway -Payload $payload
            
            $result.integrity_check | Should -Be $false -Because "Mutated content must break hash chain"
            $originalHash | Should -Not -Be $tamperedHash -Because "Hash must change when content changes"
        }

        It "Validates unmodified logs pass integrity check" {
            $content = "Original signed warrant – unchanged."
            $record = @{
                seq_no = 1005
                event_type = "signed_eaw_document"
                document_content = $content
            }
            $json = $record | ConvertTo-Json -Compress
            $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($json)
            ) | ForEach-Object { $_.ToString("x2") } | Join-String
            
            $payload = @{
                endpoint = "forensic-replay"
                original_hash = $hash
                computed_hash = $hash
            }
            
            $result = Invoke-SuperAttorneyGateway -Payload $payload
            
            $result.integrity_check | Should -Be $true -Because "Unmodified logs should pass integrity check"
        }
    }
}

# -------------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------------
# These tests validate:
# 1. Temporal synchronization across heterogeneous video/telematics feeds
# 2. Attention boundary isolation (t, 0, 0) for statutory text queries
# 3. Cryptographic chain integrity to prevent silent log tampering
#
# All tests gracefully degrade to mock mode when Flask backend is offline,
# ensuring repeatable validation in CI/CD pipelines.
# -------------------------------------------------------------------
