import type { PhantomTraceDataService } from "./dataService";
import { LocalDataService } from "./localDataService";
import { ApiDataService } from "./apiDataService";

/**
 * Default local data service instance (Phase 2).
 */
export const localDataService = new LocalDataService();

/**
 * API-connected data service instance (Phase 3).
 * Interacts with PhantomTrace Express API and Firebase Admin SDK / Cloud Firestore.
 */
export const apiDataService = new ApiDataService();

/**
 * Primary singleton PhantomTrace data service instance for the React dashboard.
 * Points to apiDataService (with automatic transparent fallback to localDataService).
 */
export const dataService: PhantomTraceDataService = apiDataService;

/**
 * Backward compatibility alias for any existing consumer.
 */
export const apiService = dataService;

export * from "./dataService";
export * from "./localDataService";
export * from "./apiDataService";
