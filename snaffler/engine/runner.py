"""
Main Snaffler controller - orchestrates all components
"""
import logging
from datetime import datetime

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.domain_pipeline import DomainPipeline
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.utils.logger import print_completion_stats

logger = logging.getLogger('snaffler')


class SnafflerRunner:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.start_time = None

        # ---------- Pipelines ----------
        self.share_pipeline = SharePipeline(cfg=cfg)
        self.file_pipeline = FilePipeline(cfg=cfg)

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        try:
            # ---------- Direct UNC paths ----------
            if self.cfg.targets.path_targets:
                self.file_pipeline.run(self.cfg.targets.path_targets)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                share_paths = self.share_pipeline.run(self.cfg.targets.computer_targets)
                if share_paths:
                    self.file_pipeline.run(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg)
                computers = domain_pipeline.run()
                if computers:
                    share_paths = self.share_pipeline.run(computers)
                    if share_paths:
                        self.file_pipeline.run(share_paths)

            else:
                logger.error("No targets specified")
                return

            print_completion_stats(start_time=self.start_time)

        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            raise
