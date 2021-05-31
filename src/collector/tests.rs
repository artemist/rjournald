use super::util::CgroupPath;

#[test]
fn parse_system_service_cgroup() {
    let parsed = CgroupPath::from_slice(b"/system.slice/dbus.service");
    assert_eq!(
        parsed,
        CgroupPath {
            system_slice: Some(Box::new(*b"system.slice")),
            system_unit: Some(Box::new(*b"dbus.service")),
            user_slice: None,
            user_unit: None
        }
    );
}

#[test]
fn parse_user_service_cgroup() {
    let parsed = CgroupPath::from_slice(
        b"/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service",
    );
    assert_eq!(
        parsed,
        CgroupPath {
            system_slice: Some(Box::new(*b"user-1000.slice")),
            system_unit: Some(Box::new(*b"user@1000.service")),
            user_slice: Some(Box::new(*b"app.slice")),
            user_unit: Some(Box::new(*b"dbus.service"))
        }
    );
}

#[test]
fn parse_init_cgroup() {
    let parsed = CgroupPath::from_slice(b"/init.scope");
    assert_eq!(
        parsed,
        CgroupPath {
            system_slice: Some(Box::new(*b"-.slice")),
            system_unit: Some(Box::new(*b"init.scope")),
            user_slice: None,
            user_unit: None
        }
    );
}
