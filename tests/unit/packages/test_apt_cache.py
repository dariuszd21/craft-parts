# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright 2020-2021 Canonical Ltd.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License version 3 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from pathlib import Path
from typing import cast
from unittest.mock import call

import apt.package
import pytest
from craft_parts.packages import apt_cache, errors
from craft_parts.packages.apt_cache import AptCache
from typing_extensions import Self


class LogInstallProgress(apt.progress.base.InstallProgress):
    """Class for tracking apt installation progress."""

    def __init__(self, logger_func=logger) -> None:
        super().__init__()
        self._logger_func = logger_func

    def __enter__(self) -> Self:
        return super().__enter__()

    def __exit__(self, type, value, traceback):
        # type: (object, object, object) -> None
        super().__exit__(type, value, traceback)

    def error(self, pkg, errormsg):
        # type: (str, str) -> None
        """(Abstract) Called when a error is detected during the install."""
        super().error(pkg, errormsg)
        self._logger_func.info("Error occurred: %s", errormsg)

    def conffile(self, current, new):
        # type: (str, str) -> None
        super().conffile(current, new)
        self._logger_func.info("Conffile called current: %s new: %s", current, new)

    def status_change(self, pkg, percent, status):
        # type: (str, float, str) -> None
        """(Abstract) Called when the APT status changed."""
        super().status_change(pkg, percent, status)
        self._logger_func.info("Status changed %s %s %s", pkg, percent, status)

    def dpkg_status_change(self, pkg, status):
        # type: (str, str) -> None
        """(Abstract) Called when the dpkg status changed."""
        super().dpkg_status_change(pkg, status)
        self._logger_func.info("DPKG status change: %s, (package %s)", status, pkg)

    def processing(self, pkg, stage):
        # type: (str, str) -> None
        """(Abstract) Sent just before a processing stage starts.

        The parameter 'stage' is one of "upgrade", "install"
        (both sent before unpacking), "configure", "trigproc", "remove",
        "purge". This method is used for dpkg only.
        """
        super().processing(pkg, stage)
        self._logger_func.info("Processing package: %s (stage %s)", pkg, stage)


class TestAptStageCache:
    """Make sure the stage cache is working correctly.

    This are expensive tests, but is much more valuable than using mocks.
    When adding tests, consider adding it to test_stage_packages(), or
    create mocks.
    """

    def test_stage_packages(self, tmpdir):
        fetch_dir_path = Path(tmpdir, "debs")
        fetch_dir_path.mkdir(exist_ok=True, parents=True)
        stage_cache = Path(tmpdir, "cache")
        stage_cache.mkdir(exist_ok=True, parents=True)

        AptCache.configure_apt("test_stage_packages")
        with AptCache(stage_cache=stage_cache) as cache:
            package_names = {"pciutils"}
            filtered_names = {
                "base-files",
                "libc6",
                "libkmod2",
                "libudev1",
                "zlib1g",
                # dependencies in focal
                "dpkg",
                "libacl1",
                "libbz2-1.0",
                "libcrypt1",
                "liblzma5",
                "libpcre2-8-0",
                "libselinux1",
                "libzstd1",
                "pci.ids",
                "perl-base",
                "tar",
                # dependencies in jammy
                "gcc-13-base",
                "libgcc-s1",
            }

            cache.mark_packages(package_names)
            cache.unmark_packages(unmark_names=filtered_names)

            marked_packages = cache.get_packages_marked_for_installation()
            assert sorted([name for name, _ in marked_packages]) == [
                "libpci3",
                "pciutils",
            ]

            names = []
            for pkg_name, pkg_version, dl_path in cache.fetch_archives(fetch_dir_path):
                names.append(pkg_name)
                assert dl_path.exists()
                assert dl_path.parent == fetch_dir_path
                assert isinstance(pkg_version, str)

            assert sorted(names) == ["libpci3", "pciutils"]

    def test_packages_without_candidate(self, tmpdir, mocker):
        class MockPackage:
            def __init__(self):
                self.name = "mock"
                self.marked_install = True
                self.candidate = None

        stage_cache = Path(tmpdir, "cache")
        stage_cache.mkdir(exist_ok=True, parents=True)
        bad_pkg = cast(apt.package.Package, MockPackage())
        mocker.patch("apt.cache.Cache.get_changes", return_value=[bad_pkg])

        with AptCache(stage_cache=stage_cache) as cache:
            with pytest.raises(errors.PackagesNotFound) as raised:
                cache.get_packages_marked_for_installation()

        assert raised.value.packages == ["mock"]

    def test_marked_install_without_candidate(self, tmpdir, mocker):
        class MockPackage:
            def __init__(self):
                self.name = "mock"
                self.installed = False
                self.marked_install = False
                self.candidate = None

        bad_pkg = cast(apt.package.Package, MockPackage())

        with pytest.raises(errors.PackageNotFound) as raised:
            apt_cache._verify_marked_install(bad_pkg)

        assert raised.value.package_name == "mock"

    def test_unmark_packages_without_candidate(self, tmpdir, mocker):
        class MockPackage:
            def __init__(self):
                self.name = "mock"
                self.marked_install = True
                self.candidate = None

        stage_cache = Path(tmpdir, "cache")
        stage_cache.mkdir(exist_ok=True, parents=True)
        bad_pkg = cast(apt.package.Package, MockPackage())
        mocker.patch("apt.cache.Cache.get_changes", return_value=[bad_pkg])

        with AptCache(stage_cache=stage_cache) as cache:
            with pytest.raises(errors.PackageNotFound) as raised:
                cache.unmark_packages({"mock"})

        assert raised.value.package_name == "mock"


class TestMockedApt:
    """Tests using mocked apt utility."""

    def test_configure(self, mocker):
        fake_apt_pkg = mocker.patch("craft_parts.packages.apt_cache.apt_pkg")

        AptCache().configure_apt("test_configure")
        # fmt: off
        assert fake_apt_pkg.mock_calls == [
            call.config.set("Apt::Install-Recommends", "False"),
            call.config.set("Acquire::AllowInsecureRepositories", "False"),
            call.config.set("Dir::Etc::Trusted", "/etc/apt/trusted.gpg"),
            call.config.set("Dir::Etc::TrustedParts", "/etc/apt/trusted.gpg.d/"),
            call.config.set("Dir::State", "/var/lib/apt"),
            call.config.clear("APT::Update::Post-Invoke-Success"),
        ]
        # fmt: on

    def test_configure_in_snap(self, mocker, tmpdir):
        fake_apt_pkg = mocker.patch("craft_parts.packages.apt_cache.apt_pkg")

        snap_dir = str(tmpdir)
        mocker.patch.dict(
            os.environ, {"SNAP_NAME": "test_configure_in_snap", "SNAP": snap_dir}
        )
        AptCache().configure_apt("test_configure_in_snap")
        # fmt: off
        assert fake_apt_pkg.mock_calls == [
            call.config.set("Apt::Install-Recommends", "False"),
            call.config.set("Acquire::AllowInsecureRepositories", "False"),
            call.config.set("Dir", snap_dir + "/usr/lib/apt"),
            call.config.set("Dir::Bin::methods", snap_dir + "/usr/lib/apt/methods/"),
            call.config.set("Dir::Bin::solvers::", snap_dir + "/usr/lib/apt/solvers/"),
            call.config.set("Dir::Bin::apt-key", snap_dir + "/usr/bin/apt-key"),
            call.config.set("Apt::Key::gpgvcommand", snap_dir + "/usr/bin/gpgv"),
            call.config.set("Dir::Etc::Trusted", "/etc/apt/trusted.gpg"),
            call.config.set("Dir::Etc::TrustedParts", "/etc/apt/trusted.gpg.d/"),
            call.config.set("Dir::State", "/var/lib/apt"),
            call.config.clear("APT::Update::Post-Invoke-Success"),
        ]
        # fmt: on

    def test_stage_cache(self, tmpdir, mocker):
        stage_cache = Path(tmpdir, "cache")
        stage_cache.mkdir(exist_ok=True, parents=True)
        fake_apt = mocker.patch("craft_parts.packages.apt_cache.apt")

        with AptCache(stage_cache=stage_cache) as _:
            pass

        assert fake_apt.mock_calls == [
            call.cache.Cache(rootdir=str(stage_cache), memonly=True),
            call.cache.Cache().close(),
        ]

    def test_host_cache_setup(self, mocker):
        fake_apt = mocker.patch("craft_parts.packages.apt_cache.apt")

        with AptCache() as _:
            pass

        assert fake_apt.mock_calls == [
            call.cache.Cache(rootdir="/"),
            call.cache.Cache().close(),
        ]


class TestAptReadonlyHostCache:
    """Host cache tests."""

    def test_host_is_package_valid(self):
        with AptCache() as cache:
            assert cache.is_package_valid("apt")
            assert cache.is_package_valid("fake-news-bears") is False

    def test_host_get_installed_packages(self):
        with AptCache() as cache:
            installed_packages = cache.get_installed_packages()
            assert isinstance(installed_packages, dict)
            assert "apt" in installed_packages
            assert "fake-news-bears" not in installed_packages

    def test_host_get_installed_version(self):
        with AptCache() as cache:
            assert isinstance(cache.get_installed_version("apt"), str)
            assert cache.get_installed_version("fake-news-bears") is None


def test_ignore_unreadable_files(tmp_path):
    unreadable = tmp_path / "unreadable"
    unreadable.touch(000)
    readable = tmp_path / "readable"
    readable.touch()

    result = apt_cache._ignore_unreadable_files(tmp_path, ["unreadable", "readable"])

    assert result == ["unreadable"]
