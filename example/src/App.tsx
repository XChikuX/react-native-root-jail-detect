import { useState, useEffect } from 'react';
import {
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  Alert,
  ActivityIndicator,
  TouchableOpacity,
  SafeAreaView,
  Share,
  Platform,
} from 'react-native';
import {
  checkDetailed,
  configure,
  getDetectionReasons,
  startSecurityWatchdog,
  stopSecurityWatchdog,
  type CompromiseAssessment,
} from '@psync/anti-jailbreak';

function App() {
  const [loading, setLoading] = useState(true);
  const [isCompromised, setIsCompromised] = useState<boolean | null>(null);
  const [isEmu, setIsEmu] = useState<boolean | null>(null);
  const [isDebugger, setIsDebugger] = useState<boolean | null>(null);
  const [detectionReasons, setDetectionReasons] = useState<string[]>([]);
  const [detailed, setDetailed] = useState<CompromiseAssessment | null>(null);
  const [watchdogRunning, setWatchdogRunning] = useState(false);
  const [diagnosticsJson, setDiagnosticsJson] = useState<string | null>(null);
  const [diagnosticsRunning, setDiagnosticsRunning] = useState(false);

  const checkDeviceSecurity = async () => {
    setLoading(true);
    try {
      // Run one structured pass. The example derives display values locally so
      // rechecking the UI never invokes the native detectors multiple times.
      const result = await checkDetailed();
      setDetailed(result);

      setIsCompromised(result.compromised);
      // Emulator/simulator detection matches the public `isEmulator()` wrapper:
      // any platform-prefixed `*.emulator*` / `*.simulator*` signal id wins.
      setIsEmu(
        result.signals.some(
          (signal) =>
            signal.id.startsWith('android.emulator') ||
            signal.id.startsWith('ios.simulator')
        )
      );
      setIsDebugger(result.debuggerDetected);
      // Use the public wrapper so reasons stay human-readable and stay in sync
      // with the library's signal-id -> text catalog (avoids showing raw ids).
      setDetectionReasons(await getDetectionReasons());

      if (result.compromised) {
        Alert.alert(
          'Security Warning',
          'This device appears to be rooted/jailbroken. Some features may be disabled for security reasons.',
          [{ text: 'OK' }]
        );
      }
    } catch (error) {
      console.error('Security check failed:', error);
      Alert.alert('Error', 'Failed to perform security check');
    } finally {
      setLoading(false);
    }
  };

  const startWatchdog = () => {
    // LOG_ONLY avoids terminating the example on emulators/simulators, which
    // are detected as compromised by design. It still exercises the full
    // background thread lifecycle and tick path.
    startSecurityWatchdog({ intervalMs: 5000, protectionMode: 'LOG_ONLY' });
    setWatchdogRunning(true);
  };

  const stopWatchdog = () => {
    stopSecurityWatchdog();
    setWatchdogRunning(false);
  };

  // WS-F measurement instrumentation (PLAN.md): opt-in evidence-level export
  // of one structured pass for the on-device corpus. Local share sheet only —
  // no network. Honest scope note: this exports the assessment plus per-signal
  // evidence; findings suppressed BY DESIGN (stock OEM overlays at subpaths,
  // fully cleaned DenyList namespaces) never appear, and raw /proc lines are
  // not exposed through the public API. Evidence is gated behind the global
  // `includeEvidence` flag, so it is enabled for this single pass and restored
  // afterwards to keep the regular demo path evidence-free.
  const runDiagnostics = async () => {
    setDiagnosticsRunning(true);
    try {
      configure({ includeEvidence: true });
      const result = await checkDetailed();
      const payload = {
        schema: 'rootjaildetect-diagnostics/1',
        capturedAt: new Date().toISOString(),
        platform: Platform.OS,
        osVersion: String(Platform.Version),
        partial: result.partial,
        score: Math.round(result.score),
        confidence: result.confidence,
        compromised: result.compromised,
        debuggerDetected: result.debuggerDetected,
        elapsedMs: Math.round(result.elapsedMs),
        signals: result.signals.map((signal) => ({
          id: signal.id,
          category: signal.category,
          severity: signal.severity,
          score: signal.score,
          reliability: signal.reliability,
          detected: signal.detected,
          unavailable: signal.unavailable ?? undefined,
          evidence: signal.evidence ?? undefined,
        })),
      };
      const json = JSON.stringify(payload, null, 2);
      setDiagnosticsJson(json);
      await Share.share({
        message: json,
        title: 'anti-jailbreak diagnostics',
      });
    } catch (error) {
      console.error('Diagnostics failed:', error);
      Alert.alert('Error', 'Failed to run diagnostics export');
    } finally {
      try {
        configure({ includeEvidence: false });
      } catch {
        // Restoring the flag must never mask the original failure.
      }
      setDiagnosticsRunning(false);
    }
  };

  useEffect(() => {
    checkDeviceSecurity();
  }, []);

  const getStatusColor = (value: boolean | null) => {
    if (value === null) return '#999';
    return value ? '#ff4444' : '#00C851';
  };

  const getScoreColor = (score: number | undefined) => {
    if (score === undefined) return '#999';
    return score > 0 ? '#ff9800' : '#00C851';
  };

  const getStatusText = (value: boolean | null) => {
    if (value === null) return 'Checking...';
    return value ? 'YES' : 'NO';
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <ScrollView contentInsetAdjustmentBehavior="automatic">
        <View style={styles.header}>
          <Text style={styles.title}>Device Security Check</Text>
          <Text style={styles.subtitle}>
            Comprehensive security analysis of your device
          </Text>
        </View>

        {loading ? (
          <View style={styles.loadingContainer}>
            <ActivityIndicator size="large" color="#007AFF" />
            <Text style={styles.loadingText}>Analyzing device security...</Text>
          </View>
        ) : (
          <View style={styles.resultsContainer}>
            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Device Compromised</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isCompromised) },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {getStatusText(isCompromised)}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Checks if device is rooted (Android) or jailbroken (iOS)
              </Text>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Emulator/Simulator</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isEmu) },
                  ]}
                >
                  <Text style={styles.statusText}>{getStatusText(isEmu)}</Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Detects if app is running in emulator or simulator
              </Text>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Debugger Attached</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getStatusColor(isDebugger) },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {getStatusText(isDebugger)}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Checks if debugger is currently attached
              </Text>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Detailed Risk Result</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: getScoreColor(detailed?.score) },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {detailed ? `${Math.round(detailed.score)}` : '...'}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Primary scored API. Score 0-100, confidence:{' '}
                 {detailed?.confidence ?? '—'}
                 {detailed?.partial ? ' (partial)' : ''}
               </Text>
              <Text style={styles.resultDescription}>
                Completed in {detailed ? `${Math.round(detailed.elapsedMs)} ms` : '...'}
              </Text>
              {detailed && detailed.signals.length > 0 && (
                <View style={styles.warningBox}>
                  <Text style={styles.warningTitle}>Signals</Text>
                  {detailed.signals.map((signal, index) => (
                    <Text key={index} style={styles.warningText}>
                      - {signal.id} [{signal.category}] ({signal.severity},{' '}
                      {signal.score})
                      {signal.unavailable ? ' unavailable' : ''}
                    </Text>
                  ))}
                </View>
              )}
              {detailed &&
                detailed.signals.some(
                  (signal) =>
                    signal.id === 'android.modules.magisk' ||
                    signal.id === 'android.modules.hiding' ||
                    signal.id === 'android.modules.spoofing'
                ) && (
                  <View style={styles.infoBox}>
                    <Text style={styles.infoTitle}>Module Tree</Text>
                    <Text style={styles.infoText}>
                      The module directory was readable. Enable evidence in{' '}
                      <Text style={styles.codeText}>configure()</Text> to show
                      redacted module details.
                    </Text>
                  </View>
                )}
              {detailed &&
                detailed.signals.some((signal) =>
                  signal.id.startsWith('android.props.inconsistent_')
                ) && (
                  <View style={styles.infoBox}>
                    <Text style={styles.infoTitle}>Property Consistency</Text>
                    {detailed.signals
                      .filter((signal) =>
                        signal.id.startsWith('android.props.inconsistent_')
                      )
                      .map((signal) => (
                        <Text key={signal.id} style={styles.infoText}>
                          {signal.id}: {signal.evidence ?? 'candidate mismatch detected'}
                        </Text>
                      ))}
                  </View>
                )}
            </View>

            <TouchableOpacity
              style={styles.recheckButton}
              onPress={checkDeviceSecurity}
            >
              <Text style={styles.recheckButtonText}>Recheck Security</Text>
            </TouchableOpacity>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Security Watchdog</Text>
                <View
                  style={[
                    styles.statusBadge,
                    { backgroundColor: watchdogRunning ? '#00C851' : '#999' },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {watchdogRunning ? 'RUNNING' : 'STOPPED'}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Background periodic check. LOG_ONLY mode prevents the example app
                from terminating on emulators/simulators.
              </Text>
              <View style={styles.watchdogButtonRow}>
                <TouchableOpacity
                  style={[styles.watchdogButton, styles.watchdogStartButton]}
                  onPress={startWatchdog}
                  disabled={watchdogRunning}
                >
                  <Text style={styles.watchdogButtonText}>Start</Text>
                </TouchableOpacity>
                <TouchableOpacity
                  style={[styles.watchdogButton, styles.watchdogStopButton]}
                  onPress={stopWatchdog}
                  disabled={!watchdogRunning}
                >
                  <Text style={styles.watchdogButtonText}>Stop</Text>
                </TouchableOpacity>
              </View>
            </View>

            <View style={styles.resultCard}>
              <View style={styles.resultHeader}>
                <Text style={styles.resultLabel}>Measurement Diagnostics</Text>
                <View
                  style={[
                    styles.statusBadge,
                    {
                      backgroundColor: diagnosticsJson
                        ? '#007AFF'
                        : '#999',
                    },
                  ]}
                >
                  <Text style={styles.statusText}>
                    {diagnosticsJson ? 'READY' : 'IDLE'}
                  </Text>
                </View>
              </View>
              <Text style={styles.resultDescription}>
                Opt-in corpus export for the on-device measurement program.
                Runs one evidence-enabled pass and opens the local share sheet
                (no network). Findings suppressed by design — stock OEM overlay
                layering, fully cleaned DenyList namespaces — do not appear;
                this is an evidence-level export, not raw /proc access.
              </Text>
              <View style={styles.watchdogButtonRow}>
                <TouchableOpacity
                  style={[
                    styles.watchdogButton,
                    styles.diagnosticsRunButton,
                  ]}
                  onPress={runDiagnostics}
                  disabled={diagnosticsRunning}
                >
                  <Text style={styles.watchdogButtonText}>
                    {diagnosticsRunning ? 'Running…' : 'Run & Export'}
                  </Text>
                </TouchableOpacity>
              </View>
              {diagnosticsJson && (
                <View style={styles.infoBox}>
                  <Text style={styles.infoTitle}>
                    Last Export ({diagnosticsJson.length} chars)
                  </Text>
                  <Text
                    style={[styles.codeText, styles.diagnosticsOutput]}
                    numberOfLines={200}
                  >
                    {diagnosticsJson}
                  </Text>
                </View>
              )}
            </View>

            {detectionReasons && detectionReasons.length > 0 && (
              <View style={styles.warningBox}>
                <Text style={styles.warningTitle}>Security Notice</Text>
                {detectionReasons.map((reason, index) => (
                  <Text key={index} style={styles.warningText}>
                    - {reason}
                  </Text>
                ))}
              </View>
            )}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  header: {
    padding: 20,
    backgroundColor: '#fff',
    borderBottomWidth: 1,
    borderBottomColor: '#e0e0e0',
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
    marginBottom: 8,
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
  },
  loadingContainer: {
    padding: 40,
    alignItems: 'center',
  },
  loadingText: {
    marginTop: 16,
    fontSize: 16,
    color: '#666',
  },
  resultsContainer: {
    padding: 16,
  },
  resultCard: {
    backgroundColor: '#fff',
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  resultHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  resultLabel: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333',
  },
  statusBadge: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 16,
  },
  statusText: {
    color: '#fff',
    fontWeight: 'bold',
    fontSize: 12,
  },
  resultDescription: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
  },
  recheckButton: {
    backgroundColor: '#007AFF',
    padding: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 8,
    marginBottom: 16,
  },
  recheckButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  watchdogButtonRow: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 12,
  },
  watchdogButton: {
    flex: 1,
    padding: 12,
    borderRadius: 8,
    alignItems: 'center',
  },
  watchdogStartButton: {
    backgroundColor: '#00C851',
  },
  watchdogStopButton: {
    backgroundColor: '#ff4444',
  },
  watchdogButtonText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '600',
  },
  diagnosticsRunButton: {
    backgroundColor: '#007AFF',
  },
  diagnosticsOutput: {
    maxHeight: 240,
    fontSize: 11,
    lineHeight: 15,
  },
  warningBox: {
    backgroundColor: '#fff3cd',
    borderLeftWidth: 4,
    borderLeftColor: '#ff9800',
    padding: 16,
    borderRadius: 8,
  },
  warningTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#856404',
    marginBottom: 8,
  },
  warningText: {
    fontSize: 14,
    color: '#856404',
    lineHeight: 20,
  },
  infoBox: {
    backgroundColor: '#e8f4ff',
    borderLeftWidth: 4,
    borderLeftColor: '#007AFF',
    padding: 16,
    borderRadius: 8,
    marginTop: 12,
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#075985',
    marginBottom: 8,
  },
  infoText: {
    fontSize: 14,
    color: '#075985',
    lineHeight: 20,
  },
  codeText: {
    fontFamily: 'monospace',
  },
});

export default App;
