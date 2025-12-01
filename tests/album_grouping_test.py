import unittest
from pathlib import Path

from gpmc.utils import compute_album_groups, sanitize_album_name


class TestAlbumGrouping(unittest.TestCase):
    def test_fixed_album_name_groups_all(self):
        results = {
            str(Path("C:/Fotos/Viaje1/img1.jpg")): "k1",
            str(Path("C:/Fotos/Viaje1/img2.jpg")): "k2",
        }
        groups = compute_album_groups(results, "Vacaciones")
        self.assertEqual(set(groups.keys()), {sanitize_album_name("Vacaciones")})
        self.assertEqual(groups["Vacaciones"], ["k1", "k2"])

    def test_auto_groups_by_common_base(self):
        results = {
            str(Path("C:/Fotos/Viaje1/img1.jpg")): "k1",
            str(Path("C:/Fotos/Viaje1/Sub/img2.jpg")): "k2",
            str(Path("C:/Fotos/Viaje2/img3.jpg")): "k3",
        }
        groups = compute_album_groups(results, "AUTO")
        # Common base expected to be 'Fotos'
        self.assertIn("Fotos/Viaje1", groups)
        self.assertIn("Fotos/Viaje2", groups)
        self.assertEqual(groups["Fotos/Viaje1"], ["k1", "k2"])
        self.assertEqual(groups["Fotos/Viaje2"], ["k3"])

    def test_auto_with_custom_base(self):
        results = {
            str(Path("C:/Fotos/Viaje1/img1.jpg")): "k1",
            str(Path("C:/Fotos/Viaje1/Sub/img2.jpg")): "k2",
            str(Path("C:/Fotos/Viaje1/Sub/img3.jpg")): "k3",
        }
        groups = compute_album_groups(results, "AUTO=C:/Fotos/Viaje1")
        self.assertIn("Viaje1", groups)
        self.assertIn("Viaje1/Sub", groups)
        self.assertEqual(groups["Viaje1"], ["k1"])
        self.assertEqual(groups["Viaje1/Sub"], ["k2", "k3"])

    def test_same_folder_same_album(self):
        results = {
            str(Path("C:/Fotos/Viaje1/Sub/img1.jpg")): "k1",
            str(Path("C:/Fotos/Viaje1/Sub/img2.jpg")): "k2",
        }
        groups = compute_album_groups(results, "AUTO")
        # Expect both keys under same album path
        albums = list(groups.keys())
        self.assertEqual(len(albums), 1)
        self.assertEqual(groups[albums[0]], ["k1", "k2"])  # order preserved by insertion


if __name__ == "__main__":
    unittest.main()