class FetchService {
    static getData(url, onSuccess, onError) {
        $.get(url, onSuccess).fail(onError);
    }

    static fetchJSON(url, onSuccess, onError) {
        fetch(url)
            .then(response => response.json())
            .then(onSuccess)
            .catch(onError);
    }
}
