plugins {
    `java-library`
    `maven-publish`
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
            "Automatic-Module-Name" to "io.github.wshenk.keysigning",
        )
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name = "KeySigningJavaLib"
                description = "A small, JDK-only library for signing and verifying payloads."
                url = "https://github.com/wshenk/KeySigningJavaLib"
                licenses {
                    license {
                        name = "MIT License"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                scm {
                    url = "https://github.com/wshenk/KeySigningJavaLib"
                }
            }
        }
    }
    repositories {
        // Local repo under build/ so the published layout can be inspected without any credentials.
        maven {
            name = "build"
            url = uri(layout.buildDirectory.dir("repo"))
        }
    }
}
