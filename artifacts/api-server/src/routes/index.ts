import { Router, type IRouter } from "express";
import healthRouter from "./health";
import gauthMgmtRouter from "./gauth-mgmt";
import gauthPepRouter from "./gauth-pep";
import gauthVciVpRouter from "./gauth-vci-vp";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/gauth/mgmt/v1", gauthMgmtRouter);
router.use("/gauth/pep/v1", gauthPepRouter);
router.use("/gauth", gauthVciVpRouter);

export default router;
