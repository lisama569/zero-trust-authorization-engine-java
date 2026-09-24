package com.github.lisama569.zerotrustauthorizationenginejava.directory;

import com.github.lisama569.zerotrustauthorizationenginejava.model.Resource;
import com.github.lisama569.zerotrustauthorizationenginejava.model.Subject;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 本地状态模拟的主体/资源目录。
 * 演示环境下由 SeedDataInitializer 填充固定数据。
 */
@Component
public class LocalDirectory {

    private final Map<String, Subject> subjects = new ConcurrentHashMap<>();
    private final Map<String, Resource> resources = new ConcurrentHashMap<>();

    public Optional<Subject> findSubject(String subjectId) {
        return Optional.ofNullable(subjectId == null ? null : subjects.get(subjectId));
    }

    public Optional<Resource> findResource(String resourceId) {
        return Optional.ofNullable(resourceId == null ? null : resources.get(resourceId));
    }

    public void putSubject(Subject subject) {
        subjects.put(subject.getSubjectId(), subject);
    }

    public void putResource(Resource resource) {
        resources.put(resource.getResourceId(), resource);
    }
}
