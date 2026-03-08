import { Router } from "express";
import {
 createNote,
 getAllNotes,
 getNote,
 updateNote,
 deleteNote
} from "../controllers/note.controller.js";

import { verifyJwt } from "../middlewares/auth.middleware.js";

const router = Router();

router.use(verifyJwt);

router.post("/:projectId/notes", createNote);
router.get("/:projectId/notes", getAllNotes);
router.get("/:projectId/notes/:noteId", getNote);
router.put("/:projectId/notes/:noteId", updateNote);
router.delete("/:projectId/notes/:noteId", deleteNote);


export default router;