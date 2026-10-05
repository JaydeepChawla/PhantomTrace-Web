/**
 * =====================================================================
 * PHANTOMTRACE LOCAL AGENT CLIENT SERVICE
 * =====================================================================
 * Communicates with the local PhantomTrace Windows Agent (127.0.0.1:49152)
 * to provide the one-click "Scan My PC" experience.
 *
 * All operations are strictly local, read-only, and secure.
 * =====================================================================
 */

export type AgentState =
  | 'NOT_INSTALLED'
  | 'OFFLINE'
  | 'CONNECTED'
  | 'STARTING'
  | 'SCANNING'
  | 'VALIDATING'
  | 'UPLOADING'
  | 'COMPLETED'
  | 'ERROR';

export interface AgentStatus {
  connected: boolean;
  state: AgentState;
  version?: string;
  scannerAvailable?: boolean;
  cloudAuthenticated?: boolean;
  message?: string;
  elapsedSeconds?: number;
  scanSummary?: {
    totalProcesses: number;
    threatCount: number;
    highestScore: number;
    timestamp: string;
    fileSizeKb: number;
  };
  uploadResult?: {
    success: boolean;
    message: string;
    data?: any;
  };
  error?: string;
}

export class LocalAgentService {
  private agentBaseUrl = 'http://127.0.0.1:49152';

  /**
   * Diagnostic ping against the local agent HTTP server.
   */
  async checkStatus(): Promise<AgentStatus> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1800);

    try {
      const response = await fetch(`${this.agentBaseUrl}/api/status`, {
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
        },
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          connected: false,
          state: 'OFFLINE',
          message: 'PhantomTrace Agent responded with an error.',
        };
      }

      const data = await response.json();
      const rawState = (data.scanState || 'IDLE').toUpperCase();

      let mappedState: AgentState = 'CONNECTED';
      if (rawState === 'STARTING') mappedState = 'STARTING';
      else if (rawState === 'SCANNING') mappedState = 'SCANNING';
      else if (rawState === 'VALIDATING') mappedState = 'VALIDATING';
      else if (rawState === 'UPLOADING') mappedState = 'UPLOADING';
      else if (rawState === 'COMPLETED') mappedState = 'COMPLETED';
      else if (rawState === 'ERROR') mappedState = 'ERROR';

      return {
        connected: true,
        state: mappedState,
        version: data.version,
        scannerAvailable: Boolean(data.scannerAvailable),
        cloudAuthenticated: Boolean(data.cloudAuthenticated),
        message: data.scannerAvailable ? 'PhantomTrace Agent Connected' : 'Scanner executable not found',
      };
    } catch {
      clearTimeout(timeoutId);
      return {
        connected: false,
        state: 'NOT_INSTALLED',
        message: 'PhantomTrace Agent Not Installed or Offline',
      };
    }
  }

  /**
   * Triggers a real Windows process and memory scan via the local agent.
   */
  async startScan(): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${this.agentBaseUrl}/api/scan/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const data = await response.json();
      return {
        success: Boolean(data.success),
        message: data.message || data.error || 'Failed to start scan',
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      return {
        success: false,
        message: `Could not contact local agent: ${msg}`,
      };
    }
  }

  /**
   * Polls the real-time execution status of the ongoing scan.
   */
  async getScanStatus(): Promise<AgentStatus> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    try {
      const response = await fetch(`${this.agentBaseUrl}/api/scan/status`, {
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          connected: false,
          state: 'ERROR',
          message: 'Unable to retrieve scan progress.',
        };
      }

      const data = await response.json();
      const rawState = (data.state || 'IDLE').toUpperCase();

      let mappedState: AgentState = 'CONNECTED';
      if (rawState === 'STARTING') mappedState = 'STARTING';
      else if (rawState === 'SCANNING') mappedState = 'SCANNING';
      else if (rawState === 'VALIDATING') mappedState = 'VALIDATING';
      else if (rawState === 'UPLOADING') mappedState = 'UPLOADING';
      else if (rawState === 'COMPLETED') mappedState = 'COMPLETED';
      else if (rawState === 'ERROR') mappedState = 'ERROR';

      return {
        connected: true,
        state: mappedState,
        message: data.message,
        elapsedSeconds: data.elapsedSeconds,
        scanSummary: data.scanSummary,
        uploadResult: data.uploadResult,
      };
    } catch {
      clearTimeout(timeoutId);
      return {
        connected: false,
        state: 'OFFLINE',
        message: 'Lost connection to local agent.',
      };
    }
  }

  /**
   * Completes device pairing with the local agent using a short-lived pairing code.
   */
  async pairWithCode(
    pairingCode: string,
    apiUrl?: string
  ): Promise<{ success: boolean; message: string; deviceId?: string }> {
    try {
      const response = await fetch(`${this.agentBaseUrl}/api/pair`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          pairingCode: pairingCode.trim().toUpperCase(),
          apiUrl,
        }),
      });

      const data = await response.json();
      return {
        success: Boolean(data.success),
        message: data.message || data.error || 'Pairing completed',
        deviceId: data.deviceId,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Connection failed';
      return {
        success: false,
        message: `Could not contact local agent for pairing: ${msg}`,
      };
    }
  }
}

export const localAgentService = new LocalAgentService();
