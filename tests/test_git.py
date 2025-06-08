import base64
import gzip
import io
import os
import shutil
import tempfile
import unittest
from tarfile import TarFile
from unittest import mock
from unittest.mock import Mock

from credsweeper import __main__ as app_main
from credsweeper.__main__ import EXIT_SUCCESS
from credsweeper.common.constants import Severity
from credsweeper.utils.util import Util


class TestGit(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None
        # * commit b7b09c8cdec2904dbb6f77eec2aa6abaef975252 (HEAD -> master)
        # | Author: Your Name <you@example.com>
        # | Date:   Sun Jun 8 16:56:48 2025 +0300
        # |
        # |     Key removed
        # |
        # * commit 9d3df94e8257240aa2b98dee47dc17992c0b7476
        #   Author: Your Name <you@example.com>
        #   Date:   Sun Jun 8 16:56:25 2025 +0300
        #
        #       Key added
        git_repo_tar_gz_base64 = """
            H4sICCSlRWgAA3NhbXBsZS50YXIA7DwNcBzVeTYMBC00Mb/JNIU+Vopl2drT/eok2ZYxko1F/SP8
            Uwi2EXu77+7Wuts974+kA+OZFiZDYICQAAmEv1APNGQwGXcYCE06odRAan4LIWVaMiWpEwqmnQAB
            p1Do9733dm/vJFkSls9kuDcwvtt773vf//t+3iqSM9yOOUd2RGGk0yn8N5ZORcP/+mNOLBWNxxKx
            RDwJz2OxJPxMUkcYLzY8x1VtQuZk1Aw16fCk86b6/Y90RFD+VmYb1VznSOnBzOWfiEVjDfnXY1TJ
            P5M+IirwCeSfjDXkX5dRK/9MtFvr0nSqxbujST2T6cym0xS+qWqnmlFptjudiqfiM9sDBZxMJieV
            fzyRrJZ/PBYHlSDRI0Ny9fiMy39s7s3X/710TGzenAfeOf3fTtzzswcGzug/cNzl+5a8Nxj9zQnd
            v/volx/+9VvRY7+1re25z698cXf65LtffybW+hfzVyy68diLb2re+0pu3xMfdF8zr/n7X0mWR/9j
            yf5bB1buP0k9Yf6e5x7f3m08WThl5XnP3v/D984rlh4cvnLzgmPue2D3F//wtT0//s9vbOu+cuSf
            Th3u/8Llt8/7+d3a7n133froPx+/5vz/W/WXy275fd/JR5s3n4VRZf+p2FH3/7F0HP1/IhFv+P96
            jFr5J2lWSyaSnVoyFk9k4l3JqJoEcSXj8F8mBVJLZFLx2Mz2mMr/d8ZTNfIHbels+P96jLG5xRsf
            vuW7g6fN2frO6W+8f/CE/nk3fXFsyVnyqqu2DrbeEx24+ulfPPiTh+67I3PN19+M9JZO+eDN95fp
            V339itLSri1b327q7dky+K624Np5r7RdfdKlT12679RfPnfsXV/a9sauRw9mn/C6HrpAPv75XTc8
            8bnHnyy88fy1N+9+Zef9dy29ueN2eeu/FIzv/uDOg6XMxYtuSSr/O5icbw0e3H3aRfN++pb105Nu
            0246oO57W3/xxI82nb/xnJdjO49/+R/c25Rr771JfXr02/TegVfW7hi+5O17HzzuhYt/t//1V+dK
            //NnK4tnv/Q3V94YHdz8V6fZG254f/vr+0b37np/53M/7rrtOz96dezX1629iz6ya/iSnaUzvze6
            /ex1P/z5w7eUDpx63Tnb5z/7wXeuz7+5b9FZw088uiN13WvRvY9884J3Pnf+V3sXfvCjh27/0+9f
            /PQjyd/2n3fhfcWuLxzof+Hgs9K8TXd+/K83fbnttI96v3J//LXXUk8+b91/lrTjnV9d9IP/Kl70
            rUU3frj/xGV3uvfM65e2nXLGq7veKe85sPrzLS/8dljb/eaB7+19OLJ53ddaVy7fO+f3iT955Y2P
            czuP3bXsjm/UUf5V9l9SteEjcALMwP/HOyHwB3cTjTfy/7qMKvmnPwX5H5M/nP/JhvzrMWrl35XK
            dqXSiWgqG83Eo5CNxbuz3fFOqsd0molBApjN6smume0x1fkf7UxUyz8eTaUa+V9dxtjcRW3nr9kU
            7aRRiPMSsQueWvvAS4tWPUNPePeDXx8Y6X/q4sfVpiuvvufFl9f/5oFr5pz62EkfHm2UG2MWR5X9
            G2bW+pSc/4lUw//XY1TJv1v/tJz/yViiIf96jFr5J/Rsd5J2xVNpOPtVNZ7p7tIpTaZ1LZbu7o5r
            0Uw6me6c2R5Tnf+Q7o87/7H+3zj/j/wYm3vzM2ukf4zOO0f9RffeA8fd+mGq6Wq345HRW0eyg9H+
            c4957723Tv/33oNjw8r+V5ev+++Xvpy4at5P+v+8/bLH9t69Pf/NlkTM+NWK3Bkn2xfsf2Hoocf+
            7vrjb9jypd2bz0x8bP9h58E9L9vHnrllT9OGd0srr/3b6y97uufjn710R/qp/tXbPpe8IVk62uR/
            5keV/SczR9//i/5ftLPh/+sxauUPnl/XOpNxLdNJM91qtDNKU8lMtkvv7I53dWUzcBZ0R5Mz22PK
            /C+Wrun/QUaYbPj/egw//7t0zhyp/Zi5RxudxqjzYPaft6zhI3b755PkfxB+Nup/dRkh+aulUqFc
            Ul0trxSdXMRRi6UCnY09ppJ/OtFZI//OdLIR/9dlNJ/dkTHMDicvNUvNZLlJ6BiTO0GdII5mGyWX
            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
            PFJs/NkF4obruP7412orq4vxn0eaOv5sBLuxOq6//q+urVUX6/880mL9X6z/JQNa+TbqmDX/KyDz
            Y/v/9cri/qe5pJce2kZNOP+GRrjR1tKMwR4Z8n/Tl5kYt+r8CqfGF5Fo/t/e1p/SrPlfrq7H5n+1
            vL7A/51LAq2vrhKq32I2fymJ5r/AiD/e2T347sU3N17HzPlfqcXtf6srC/1/LunXrd0u0qxE8//2
            TH+UrmH/0et/DfX/hf3n9lM0/rdi+qN0Lfsfy//a+spi/OeR4uN/w6Y/SjPX/9VKbPxr6+XF+d9c
            0lVtZwvl4NeZovk/sm/LCeT66//KSm3h/zOXROOPl2n+P9P/yrXF+M8jRePvfKSr/m6hjlnr/8pa
            Yv6vry7wn+eS+LK7XlBgcKpCgSEN4B/hhwK6GW8m2CR9Rz1FLPOkR/edDMXUCPQWOYh/jVBpeMs6
            Oh+rvh9gxKXrqe18DI+DI1bwfiy+SxGvO6G7saRWjP4C9dQLVHZsQuX34ze3CwJlP1eHl5eLr337
            CP/5aaHGxJIMbMf5eHt1zDz/K8f1/2ptfWH/m0va2X2+DX/+AP/He4Tgzx//pqzK6Sd/cfRPj/7Z
            +8e/ffOfT/7n3/7mr//3v3b/cPivDz6e/9U/VP/u93+5/i//sfbvf/T13//35yV/kX5hovnPkdy3
            VsfM+b8Sv/+zurayWP/nkl4jgv8RAvXpo3y+/UBj2m8ymkrPIcjxTUU336VauMJvqq5NGCs9/8Tu
            9TCQlLAVA53tc7dtkRZpkRZpkRZpkaan/wORQSDXAPAAAA==
            """
        self.temp_dir_path = tempfile.mkdtemp(prefix=__name__)
        git_repo_tar_gz = base64.b64decode(git_repo_tar_gz_base64)
        with gzip.open(io.BytesIO(git_repo_tar_gz)) as gzipf:
            with TarFile(fileobj=io.BytesIO(gzipf.read())) as tf:
                for tfi in tf.getmembers():
                    target = os.path.join(self.temp_dir_path, tfi.name)
                    if tfi.isreg():
                        with tf.extractfile(tfi) as tfd:
                            with open(target, "wb") as f:
                                f.write(tfd.read())
                    else:
                        os.mkdir(target)

    def tearDown(self):
        shutil.rmtree(self.temp_dir_path)

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_git_n(self, mock_get_arguments) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, "report.json")
            args_mock = Mock(log='warning',
                             config_path=None,
                             path=[self.temp_dir_path],
                             git=None,
                             ref=None,
                             diff_path=None,
                             error=False,
                             json_filename=json_filename,
                             xlsx_filename=None,
                             subtext=False,
                             hashed=False,
                             sort_output=True,
                             rule_path=None,
                             jobs=1,
                             no_filters=False,
                             ml_threshold=0,
                             ml_batch_size=16,
                             ml_config=None,
                             ml_model=None,
                             ml_providers=None,
                             depth=0,
                             doc=False,
                             size_limit="1G",
                             find_by_ext=False,
                             denylist_path=None,
                             severity=Severity.INFO)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())
            # no files in last commit
            self.assertFalse(os.path.exists(json_filename))

    @mock.patch("credsweeper.__main__.get_arguments")
    def test_git_p(self, mock_get_arguments) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            json_filename = os.path.join(tmp_dir, "report.json")
            args_mock = Mock(log='warning',
                             config_path=None,
                             path=None,
                             git=self.temp_dir_path,
                             ref="b7b09c8cdec2904dbb6f77eec2aa6abaef975252",
                             diff_path=None,
                             error=False,
                             json_filename=json_filename,
                             xlsx_filename=None,
                             subtext=False,
                             hashed=False,
                             sort_output=True,
                             rule_path=None,
                             jobs=1,
                             no_filters=False,
                             ml_threshold=0,
                             ml_batch_size=16,
                             ml_config=None,
                             ml_model=None,
                             ml_providers=None,
                             depth=0,
                             doc=False,
                             size_limit="1G",
                             find_by_ext=False,
                             denylist_path=None,
                             severity=Severity.INFO)
            mock_get_arguments.return_value = args_mock
            self.assertEqual(EXIT_SUCCESS, app_main.main())

            empty_report_filename = os.path.join(tmp_dir, "report.b7b09c8cdec2904dbb6f77eec2aa6abaef975252.json")
            self.assertFalse(os.path.exists(empty_report_filename))

            full_report_filename = os.path.join(tmp_dir, "report.9d3df94e8257240aa2b98dee47dc17992c0b7476.json")
            self.assertTrue(os.path.exists(full_report_filename))
            full_report = Util.json_load(full_report_filename)
            self.assertLessEqual(1, len(full_report))
