import { Router, type IRouter } from "express";
import healthRouter from "./health";
import gauthMgmtRouter from "./gauth-mgmt";
import gauthPepRouter from "./gauth-pep";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/gauth/mgmt/v1", gauthMgmtRouter);
router.use("/gauth/pep/v1", gauthPepRouter);

export default router;
