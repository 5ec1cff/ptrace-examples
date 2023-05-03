@Suppress("DSL_SCOPE_VIOLATION")
plugins {
    alias(libs.plugins.com.android.application)
}

android {
    namespace = "io.github.a13e300.pt_injector"
    compileSdk = 33
    ndkVersion = "25.2.9519653"

    defaultConfig {
        applicationId = "io.github.a13e300.pt_injector"
        minSdk = 30
        targetSdk = 33
        versionCode = 1
        versionName = "1.0"
        externalNativeBuild {
            cmake {
                val flags = arrayOf(
                    "-fno-rtti",
                    "-fvisibility=hidden",
                    "-fvisibility-inlines-hidden",
                    "-fno-exceptions",
                    "-fno-stack-protector",
                    "-fomit-frame-pointer",
                    "-Wno-builtin-macro-redefined",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-D__FILE__=__FILE_NAME__",
                )
                cppFlags("-std=c++20", *flags)
                cFlags("-std=c18", *flags)
                arguments += "-DANDROID_STL=none"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        prefab = true
    }
}

dependencies {
    implementation(libs.cxx)
}