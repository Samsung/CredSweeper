import io
from credsweeper.utils import Util
        patch_provider = PatchProvider([file_path], DiffRowType.ADDED)
    def test_load_patch_data_io_p(self, config: Config) -> None:
        """Evaluate base load diff file with io.BytesIO"""
        file_path = SAMPLES_DIR / "password.patch"
        data = Util.read_data(str(file_path))
        io_data = io.BytesIO(data)
        patch_provider = PatchProvider([io_data], DiffRowType.ADDED)

        raw_patches = patch_provider.load_patch_data(config)

        expected = [[
            'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json',  #
            'new file mode 100644',  #
            'index 00000000..7ebf3947',  #
            '--- /dev/null',  #
            '+++ b/.changes/1.16.98.json',  #
            '@@ -0,0 +1,4 @@',  #
            '+{',  #
            '+  "category": "``cloudformation``",',  #
            '+  "password": "dkajco1"',  #
            '+}',  #
            '',  #
            ''  #
        ]]
        assert raw_patches == expected
