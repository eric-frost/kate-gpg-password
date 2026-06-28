# SPDX-FileCopyrightText: 2026 Eric Frost
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.24)
project(kategpgpassword VERSION 0.5.0)

set(QT_MIN_VERSION 6.6)
set(KF_MIN_VERSION 6.0)

find_package(ECM ${KF_MIN_VERSION} REQUIRED NO_MODULE)
set(CMAKE_MODULE_PATH ${ECM_MODULE_PATH})

include(KDEInstallDirs)
include(KDECMakeSettings)
include(KDECompilerSettings NO_POLICY_SCOPE)
include(ECMQtDeclareLoggingCategory)

find_package(Qt6 ${QT_MIN_VERSION} REQUIRED COMPONENTS Core Widgets)
find_package(KF6 ${KF_MIN_VERSION} REQUIRED COMPONENTS CoreAddons I18n TextEditor XmlGui WidgetsAddons Parts)
find_package(OpenSSL REQUIRED)

kcoreaddons_add_plugin(kategpgpassword INSTALL_NAMESPACE "kf6/ktexteditor")
target_compile_definitions(kategpgpassword PRIVATE TRANSLATION_DOMAIN="kategpgpassword")
target_sources(kategpgpassword PRIVATE kategpgpassword.cpp kategpgpassword.hpp)
target_link_libraries(kategpgpassword PRIVATE Qt6::Core Qt6::Widgets KF6::CoreAddons KF6::I18n KF6::TextEditor KF6::XmlGui KF6::WidgetsAddons KF6::Parts OpenSSL::Crypto)

install(FILES ui.rc DESTINATION ${KDE_INSTALL_KXMLGUIDIR}/kategpgpassword)
