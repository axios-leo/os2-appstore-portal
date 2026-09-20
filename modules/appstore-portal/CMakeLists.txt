# modules/appstore-portal — 模块内自治构建（Owner 见本目录 README/CODEOWNERS）
# 边界：只可依赖 os2_platform 与本模块 include/src；跨模块交互一律走契约主题。
add_executable(test_appstore_portal tests/test_appstore_portal.cpp)
target_include_directories(test_appstore_portal PRIVATE include src)
target_link_libraries(test_appstore_portal PRIVATE os2_platform)
add_test(NAME test_appstore_portal COMMAND test_appstore_portal)
add_executable(test_store_impl tests/test_store_impl.cpp)
target_include_directories(test_store_impl PRIVATE include src)
target_link_libraries(test_store_impl PRIVATE os2_platform)
add_test(NAME test_store_impl COMMAND test_store_impl)
add_executable(test_artifact_receiver tests/test_artifact_receiver.cpp)
target_include_directories(test_artifact_receiver PRIVATE include src)
target_link_libraries(test_artifact_receiver PRIVATE os2_platform)
add_test(NAME test_artifact_receiver COMMAND test_artifact_receiver)
