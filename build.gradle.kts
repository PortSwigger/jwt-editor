plugins {
    id("java")
    id("checkstyle")
}

group = "com.blackberry"
version = "2.6.1"
description = "jwt-editor"

repositories {
    mavenCentral()
    maven { url = uri("https://www.jetbrains.com/intellij-repository/releases") }
    maven { url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies/") }
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

checkstyle {
    toolVersion = "10.12.4"
}

configurations {
    create("guiGenerationTask")
}

dependencies {
    add("guiGenerationTask", libs.intellij.java.compiler.ant)

    compileOnly(libs.montoya.api)

    implementation(libs.bcprov)
    implementation(libs.bcpkix)
    implementation(libs.intellij.gui.forms)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.deltahex)
    implementation(libs.rsyntaxtextarea)
    implementation(libs.json)

    testImplementation(libs.bcprov)
    testImplementation(libs.bcpkix)
    testImplementation(libs.montoya.api)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.assertj.core)
    testImplementation(libs.mockito.core)

    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.withType<Checkstyle> {
    reports {
        xml.required = false
        html.required = true
    }
}

tasks.withType<JavaCompile> {
    val mainSourceSets = project.sourceSets["main"]

    doLast {
        mainSourceSets.output.classesDirs.forEach { mkdir(it) }

        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "javac2",
                "classname" to "com.intellij.ant.Javac2",
                "classpath" to configurations["guiGenerationTask"].asPath
            )
        }

        ant.withGroovyBuilder {
            "javac2"(
                "srcdir" to mainSourceSets.java.srcDirs.joinToString(":"),
                "classpath" to mainSourceSets.compileClasspath.asPath,
                "destdir" to mainSourceSets.output.classesDirs.singleFile,
                "release" to targetCompatibility.toString(),
                "includeAntRuntime" to false
            )
        }
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()

    systemProperty("user.timezone", "UTC")
}

tasks.named<Jar>("jar") {
    dependsOn("test")
    archiveBaseName.set(project.name)
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(
        configurations.runtimeClasspath.get().map {
            if (it.isDirectory) it else zipTree(it)
                .matching {
                    exclude(
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler.class",
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler\$1.class",
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler\$2.class",
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler\$BinaryDataClipboardData.class",
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler\$ClipboardData.class",
                        "org/exbin/deltahex/swing/DefaultCodeAreaCommandHandler\$CodeDataClipboardData.class",
                        "META-INF/BC2048KE.DSA",
                        "META-INF/BC2048KE.SF",
                        "META-INF/LICENSE"
                    )
                }
        }
    )

    from(rootDir) {
        include("LICENSE.md")
        into("META-INF")
    }
}
