import { useState, useEffect, useCallback } from 'react';
import { dataService } from '../services';
import type { Process, ThreatLevel } from '../types';

export function useProcessData(selectedPid?: number) {
  const [processes, setProcesses] = useState<Process[]>([]);
  const [currentProcess, setCurrentProcess] = useState<Process | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchProcesses = useCallback(async () => {
    try {
      setError(null);
      const data = await dataService.getProcesses();
      setProcesses(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch process telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchProcessByPid = useCallback(async (pid: number) => {
    try {
      setError(null);
      const proc = await dataService.getProcess(pid);
      setCurrentProcess(proc);
      return proc;
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to fetch PID ${pid}`);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let active = true;
    dataService.getProcesses()
      .then((data) => {
        if (active) {
          setProcesses(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err instanceof Error ? err.message : 'Failed to fetch process telemetry');
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (selectedPid === undefined || isNaN(selectedPid)) {
      return;
    }
    let active = true;
    dataService.getProcess(selectedPid)
      .then((proc) => {
        if (active) {
          setCurrentProcess(proc);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (active) {
          setError(err instanceof Error ? err.message : `Failed to fetch PID ${selectedPid}`);
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [selectedPid]);

  const filterProcesses = useCallback((
    search: string,
    levelFilter: ThreatLevel | 'ALL' | string,
    onlyCorrelated: boolean = false
  ) => {
    return processes.filter(p => {
      const pPath = p.path || p.executablePath || '';
      const pUser = p.userContext || '';
      const matchesSearch =
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.pid.toString().includes(search) ||
        pPath.toLowerCase().includes(search.toLowerCase()) ||
        pUser.toLowerCase().includes(search.toLowerCase());

      const matchesLevel = levelFilter === 'ALL' || (p.threatLevel as string) === levelFilter || (p.threatLevel as string).toUpperCase() === levelFilter.toUpperCase();
      const matchesCorrelation = !onlyCorrelated || p.scoreMode === 'CORRELATED' || (p.scoreMode as string) === 'Correlated';

      return matchesSearch && matchesLevel && matchesCorrelation;
    });
  }, [processes]);

  return {
    processes,
    currentProcess,
    loading,
    error,
    reloadProcesses: fetchProcesses,
    getProcessByPid: fetchProcessByPid,
    filterProcesses,
  };
}
