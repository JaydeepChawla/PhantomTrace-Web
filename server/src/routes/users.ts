import { Router, Response } from "express";
import { authMiddleware } from "../middleware/auth";
import { postgresService } from "../services/postgresService";
import type { AuthenticatedRequest } from "../types/api";

export const usersRouter = Router();

/**
 * GET /api/users/me
 * Retrieves current authenticated user profile.
 * Derives user strictly from verified Firebase token (req.ownerUid).
 */
usersRouter.get("/me", authMiddleware, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const uid = req.ownerUid!;
    const user = await postgresService.getUser(uid);

    if (!user) {
      res.status(404).json({
        error: "Not Found",
        message: "User profile not found",
      });
      return;
    }

    res.status(200).json({ user });
  } catch (err) {
    console.error("[Users Route] Error fetching user profile:", err);
    res.status(500).json({
      error: "Internal Server Error",
      message: "Failed to fetch user profile",
    });
  }
});
